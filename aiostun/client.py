
import ssl
import asyncio
import socket

from aiostun import constants
from aiostun import stun
from aiostun import attribute

class StunUdpProtocol:
    def __init__(self, client):
        """init"""
        self._client = client
        self._transport = None

    def connection_made(self, transport):
        """on connection made"""
        self._transport = transport
        self._client.send = self.send

    def datagram_received(self, data, addr):
        """on datagram received"""
        self._client.feed_data(data)

    def send(self, data):
        """send data"""
        self._transport.sendto(data)

    def error_received(self, exc):
        """on error received"""
        print('Error received:', exc)

    def connection_lost(self, exc):
        """on connection lost"""
        pass

class StunTcpProtocol:
    def __init__(self, client):
        """init"""
        self._client = client
        self._transport = None

    def connection_made(self, transport):
        """on connection made"""
        self._transport = transport
        self._client.send = self.send

    def data_received(self, data):
        """on data received"""
        self._client.feed_data(data=data)

    def send(self, data):
        """send"""
        self._transport.write(data)

    def error_received(self, exc):
        """on error received"""
        print('Error received:', exc)

    def connection_lost(self, exc):
        """on connection lost"""
        pass


class Client:
    def __init__(self, host, port=3478, family=constants.FAMILY_IP4, ipproto=constants.IPPROTO_UDP):
        """init"""
        self._host = host
        self._port = port
        self._family = family
        self._ipproto = ipproto
        self._stun_codec = stun.Codec()
        self._transport = None
        self._timeout = 5

    async def __aenter__(self):
        """aenter"""
        loop = asyncio.get_event_loop()
        kwargs = {}
        if self._family == constants.FAMILY_IP4:
            kwargs['family'] = socket.AF_INET
        if self._family == constants.FAMILY_IP6:
            kwargs['family'] = socket.AF_INET6

        if self._ipproto == constants.IPPROTO_UDP:
            kwargs['remote_addr']= self._host, self._port
            protocol = StunUdpProtocol(self._stun_codec)
            kwargs['protocol_factory'] = lambda: protocol
            coro = loop.create_datagram_endpoint(**kwargs)

        if self._ipproto == constants.IPPROTO_TCP:
            kwargs['host']= self._host
            kwargs['port'] = self._port
            protocol = StunTcpProtocol(self._stun_codec)
            kwargs['protocol_factory'] = lambda: protocol
            coro = loop.create_connection(**kwargs)

        if self._ipproto == constants.IPPROTO_TLS:
            sslcontext = ssl.create_default_context()
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
            kwargs['host']= self._host
            kwargs['port'] = self._port
            kwargs['ssl'] = sslcontext
            protocol = StunTcpProtocol(self._stun_codec)
            kwargs['protocol_factory'] = lambda: protocol
            coro = loop.create_connection(**kwargs)
        try:
            self._transport, _ = await asyncio.wait_for(coro, timeout=self._timeout)
        except asyncio.TimeoutError:
            return self
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """aexit"""
        if self._transport is not None:
            self._transport.close()

    async def bind_request(self):
        """send bind request"""
        if self._transport is None:
            return None

        m = stun.StunMessage(constants.CLASS_REQUEST, constants.METHOD_BINDING)
        request = self._stun_codec.encode(m)

        self._stun_codec.send(data=request)

        resp = await asyncio.wait_for(self._stun_codec._queue.get(), timeout=self._timeout)

        #If the message class is "Success Response" or "Error Response"
        # checks that the transaction ID matches the request
        if resp.msgclass in [ constants.CLASS_SUCCESS, constants.CLASS_ERROR]:
            if m.transaction_id != resp.transaction_id:
                return None

        return resp

    async def get_mapped_address(self):
        """get mapped address"""
        mapped_addr = {}

        resp = await self.bind_request()
        if resp is None:
            return mapped_addr

        attr = resp.get_attribute(attribute.XorMappedAddr)
        if attr is None:
            attr = resp.get_attribute(attribute.MappedAddr)
            if attr is None:
                return mapped_addr

        return attr.params