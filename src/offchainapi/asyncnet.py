# Copyright (c) The Libra Core Contributors
# SPDX-License-Identifier: Apache-2.0

from .business import BusinessNotAuthorized
from .libra_address import LibraAddress

import aiohttp, os
from aiohttp import web
from aiohttp.client_exceptions import ClientError
import asyncio
import logging


logger = logging.getLogger(name='libra_off_chain_api.asyncnet')


X_REQUEST_ID_KEY = "X-REQUEST-ID"


class NetworkException(Exception):
    pass


def get_headers(request_or_response):
    """Obtain request headers (case-insensitive)
    Args:
        request_or_response: HTTP request or request
    Returns:
        HTTP headers in dictionary form
    """
    # HTTP headers are CASE-INSENSITIVE (https://tools.ietf.org/html/rfc7230)
    # Here we convert them to uppercase
    return {k.upper(): v for k, v in request_or_response.headers.items()}


class Aionet:
    """A network client and server using aiohttp. Initialize
    the network system with a OffChainVASP instance.

    Args:
        vasp (OffChainVASP): The  OffChainVASP instance.
    """

    def __init__(self, vasp):
        self.vasp = vasp

        # For the moment hold one session per VASP.
        self.session = None
        self.app = web.Application()

        # Register routes.
        route = f"/v1/{{other_addr}}/{self.vasp.get_vasp_address().as_str()}/command"
        self.app.add_routes(
            [web.route("*", route, self.handle_request)]
        )
        logger.debug(f'Register route {route}')

        # The watchdog process variables.
        self.watchdog_period = 10.0  # seconds
        self.watchdog_task_obj = None  # Store the task here to cancel.

    async def close(self):
        ''' Close the open Http client session and the network object. '''
        if self.session is not None:
            session = self.session
            self.session = None
            await session.close()

        if self.watchdog_task_obj is not None:
            self.watchdog_task_obj.cancel()

    def schedule_watchdog(self, loop, period=10.0):
        """ Creates and schedues the watchdog periodic process.
        It logs basic statistics for all channels and retransmits.

        Args:
            loop (asyncio.AbstractEventLoopPolicy): The event loop.
            period (float, optional): The refresh period in seconds.
                Defaults to 10.0.
        """
        self.watchdog_period = period
        self.watchdog_task_obj = loop.create_task(self.watchdog_task())

    async def watchdog_task(self):
        ''' Provides a priodic debug view of pending requests and replies. '''
        logger.info('Start Network Watchdog.')
        try:
            while True:
                for k in self.vasp.channel_store:
                    channel = self.vasp.channel_store[k]

                    role = ['Client', 'Server'][channel.is_server()]
                    waiting = channel.is_server() \
                        and channel.would_retransmit()
                    me = channel.get_my_address()
                    other = channel.get_other_address()

                    # Retransmit a few of the requests here.
                    messages = await channel.package_retransmit(number=100)
                    for message in messages:
                        logger.info(
                            f'Attempt to re-transmit messages {message}.'
                        )
                        try:
                            await self.send_request(other, message.content)
                        except NetworkException as e:
                            logger.debug(
                                f'Attempt to re-transmit message {message} '
                                f'failed with error: {str(e)}'
                            )

                    len_my = len(channel.my_pending_requests)
                    logger.info(
                        f'''
                        Channel: {me.as_str()} [{role}] <-> {other.as_str()}
                        Queues: my: {len_my} (Wait: {waiting})
                        Retransmit: {channel.would_retransmit()}'''
                    )
                await asyncio.sleep(self.watchdog_period)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error('Watchdog exception', exc_info=True)
        finally:
            logger.info('Stop Network Watchdog')

    def get_url(self, base_url, other_addr_str, other_is_server=False):
        """Composes the URL for the Off-chain API VASP end point.

        Args:
            base_url (str): The base url.
            other_addr_str (str): The address of the other VASP as a string.
            other_is_server (bool, optional): Whether the other VASP is the
                server. Defaults to False.

        Returns:
            str: The complete URL for the Off-chain API VASP end point
        """
        url = f"v1/{self.vasp.get_vasp_address().as_str()}/{other_addr_str}/command"
        full_url = "/".join([base_url.rstrip("/"), url])
        logger.debug(f"Full URL: {full_url}")
        return full_url


    async def handle_request(self, request):
        """ Main Http server handler for incomming OffChainAPI requests.

        Args:
            request (aiohttp.web.Request): The request from the other VASP.

        Raises:
            aiohttp.web.HTTPUnauthorized: An exception for 401 Unauthorized.
            aiohttp.web.HTTPForbidden: An exception for 403 Forbidden.
            aiohttp.web.HTTPBadRequest: An exception for 400 Bad Request.

        Returns:
            aiohttp.web.Response: A JWS signed response.
        """

        other_addr = LibraAddress.from_encoded_str(request.match_info['other_addr'])
        logger.debug(f'Request Received from {other_addr.as_str()}')
        request_headers = get_headers(request)

        if X_REQUEST_ID_KEY not in request_headers:
            raise web.HTTPBadRequest(
                reason=f'Header needs to contain "{X_REQUEST_ID_KEY}" (case-insensitive)',
                headers={X_REQUEST_ID_KEY: 'None'}
            )
        x_request_id = request_headers[X_REQUEST_ID_KEY]
        response_headers = {X_REQUEST_ID_KEY: x_request_id}

        # Try to get a channel with the other VASP.
        try:
            channel = self.vasp.get_channel(other_addr)
        except BusinessNotAuthorized as e:
            # Raised if the other VASP is not an authorised business.
            logger.debug(f'Not Authorized', exc_info=True)
            raise web.HTTPUnauthorized(headers=response_headers)

        # Perform the request, send back the reponse.
        request_text = await request.text()

        logger.debug(f'Data Received from {other_addr.as_str()}.')
        response = await channel.parse_handle_request(request_text)

        # Return an error code upon an error
        status = 200 if not response.raw.is_failure() else 400

        # Send back the response.
        logger.debug(f'Sending back response to {other_addr.as_str()}.')
        return web.Response(status=status, text=response.content, headers=response_headers)



    async def send_request(self, other_addr, request_text):
        """ Uses an Http client to send an OffChainAPI request to another VASP.

        Args:
            other_addr (LibraAddress): The LibraAddress of the other VASP.
            request_text (dict): a JWS signed request,
                ready to be sent across the network.

        Raises:
            NetworkException: [description]
        """

        logger.debug(f'Connect to {other_addr.as_str()}')

        # Initialize the client.
        if self.session is None:
            self.session = aiohttp.ClientSession()

        # Try to get a channel with the other VASP.
        channel = self.vasp.get_channel(other_addr)

        # Get the URLs
        base_url = self.vasp.info_context.get_peer_base_url(other_addr)
        url = self.get_url(base_url, other_addr.as_str(), other_is_server=True)
        logger.debug(f'Sending post request to {url}')

        # Add a custom request header
        request_headers = {X_REQUEST_ID_KEY: get_uuid_str()}

        try:
            async with self.session.post(
                    url,
                    data=request_text,
                    headers=request_headers
            ) as response:
                response_headers = get_headers(response)
                # Check the header is correct
                if X_REQUEST_ID_KEY not in response_headers or \
                        response_headers[X_REQUEST_ID_KEY] != request_headers[X_REQUEST_ID_KEY]:
                    raise Exception(
                        f'Incorrect {X_REQUEST_ID_KEY} response header:', response_headers
                    )

                response_text = await response.text()
                # Check that there are no low-level HTTP errors.
                if response.status != 200 :
                    err_msg = f'Received status {response.status}: {response_text}'
                    raise Exception(err_msg)

                logger.debug(f'Raw response: {response_text}')

                # Wait in case the requests are sent out of order.
                res = await channel.parse_handle_response(response_text)
                logger.debug(f'Response parsed with status: {res}')

                return res

        except ClientError as e:
            logger.debug(f'ClientError {type(e)}: {e}')
            raise NetworkException(e)

    async def sequence_command(self, other_addr, command):
        ''' Sequences a new command to the local queue, ready to be
            sent to the other VASP.

            other_addr (LibraAddress) : the LibraAddress of the other VASP.
            command (ProtocolCommand) : A ProtocolCommand instance.

            Returns:
                str: str of the net message
        '''

        channel = self.vasp.get_channel(other_addr)
        request = channel.sequence_command_local(command)
        request = await channel.package_request(request)
        request = request.content
        return request

    def get_runner(self):
        ''' Gets an object to that needs to be run in an
            event loop to register the server.

            Returns:
                aiohttp.web.AppRunner: A runner for Application.

        '''
        return web.AppRunner(self.app)
