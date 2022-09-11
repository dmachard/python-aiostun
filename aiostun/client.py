
import ssl
import asyncio
import socket

from aiostun import constants
from aiostun import stun
from aiostun import attribute

class TransportProtocol:
    def __init__(self, client, proto):
        """init"""
        self._client = client
        self._transport = None
        self._proto = proto

    def connection_made(self, transport):
        """on connection made"""
        self._transport = transport
        self._client.send = self.send

    def data_received(self, data):
        """on tcp/tls data received"""
        self._client.feed_data(data=data)

    def datagram_received(self, data, addr):
        """on udp datagram received"""
        self._client.feed_data(data)

    def send(self, data):
        """send"""
        if self._proto == constants.IPPROTO_UDP:
            self._transport.sendto(data)
        if self._proto in [ constants.IPPROTO_TCP, constants.IPPROTO_TLS ]:
            self._transport.write(data)

    def error_received(self, exc):
        """on error"""
        print('error:', exc)

    def connection_lost(self, exc):
        """on connection lost"""
        pass


class Client:
    def __init__(self, host, port=3478, family=constants.FAMILY_IP4, proto=constants.IPPROTO_UDP, timeout=15):
        """init"""
        self._host = host
        self._port = port
        self._family = family
        self._ipproto = proto
        self._stun_codec = stun.Codec()
        self._transport = None
        self._timeout = timeout

    async def __aenter__(self):
        """aenter"""
        return await self.connect()

    async def __aexit__(self, exc_type, exc, tb):
        """aexit"""
        self.close()

    async def connect(self):
        """connect to remote"""
        loop = asyncio.get_event_loop()
        kwargs = {}
        if self._family == constants.FAMILY_IP4:
            kwargs['family'] = socket.AF_INET
        if self._family == constants.FAMILY_IP6:
            kwargs['family'] = socket.AF_INET6

        if self._ipproto == constants.IPPROTO_UDP:
            kwargs['remote_addr']= self._host, self._port
            protocol = TransportProtocol(self._stun_codec, self._ipproto)
            kwargs['protocol_factory'] = lambda: protocol
            coro = loop.create_datagram_endpoint(**kwargs)

        if self._ipproto == constants.IPPROTO_TCP:
            kwargs['host']= self._host
            kwargs['port'] = self._port
            protocol = TransportProtocol(self._stun_codec, self._ipproto)
            kwargs['protocol_factory'] = lambda: protocol
            coro = loop.create_connection(**kwargs)

        if self._ipproto == constants.IPPROTO_TLS:
            sslcontext = ssl.create_default_context()
            sslcontext.check_hostname = False
            sslcontext.verify_mode = ssl.CERT_NONE
            kwargs['host']= self._host
            kwargs['port'] = self._port
            kwargs['ssl'] = sslcontext
            protocol = TransportProtocol(self._stun_codec, self._ipproto)
            kwargs['protocol_factory'] = lambda: protocol
            coro = loop.create_connection(**kwargs)

        try:
            self._transport, _ = await asyncio.wait_for(coro, timeout=self._timeout)
        except asyncio.TimeoutError:
            return self
        return self

    def close(self):
        """close transport"""
        if self._transport is not None:
            self._transport.close()

    def send_request(self, req):
        """wait request"""
        if self._transport is None:
            return False

        # encode stun message
        data = self._stun_codec.encode(req)

        # send it
        self._stun_codec.send(data=data)

        return True

    async def wait_for_resp(self):
        """wait for response"""
        if self._transport is None:
            return None

        try:
            resp = await asyncio.wait_for(self._stun_codec._queue.get(), timeout=self._timeout)
        except asyncio.TimeoutError:
            return None
        return resp

    async def bind_request(self):
        """send bind request"""
        # basic stun message
        stun_req = stun.Message(constants.CLASS_REQUEST, constants.METHOD_BINDING, [])

        # send it
        success = self.send_request(req=stun_req)
        if not success:
            return {}

        # wait for response
        resp = await self.wait_for_resp()
        if resp is None:
            return None

        #If the message class is "Success Response" or "Error Response"
        # checks that the transaction ID matches the request
        if resp.msgclass in [ constants.CLASS_SUCCESS, constants.CLASS_ERROR]:
            if stun_req.transaction_id != resp.transaction_id:
                return None

        return resp

    async def get_mapped_address(self):
        """get mapped address"""
        mapped_addr = {}

        resp = await self.bind_request()
        if resp is None:
            return mapped_addr

        attr = resp.get_attribute(attribute.XorMappedAddrAttribute)
        if attr is None:
            attr = resp.get_attribute(attribute.MappedAddrAttribute)
            if attr is None:
                return mapped_addr

        return attr.params

    async def discover(self):
        """Discovery Process"""
        # https://www.rfc-editor.org/rfc/rfc3489#section-10.1

        # Test I: the client sends a STUN Binding Request to a server, 
        # without any flags set in the CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute.

        # Test II: the client sends a Binding Request with both the "change IP" and "change port" flags 
        # from the CHANGE-REQUEST attribute set.

        # Test III: the client sends a Binding Request with only the "change port" flag set.
  
        # perform test connectivity
        resp = await self.bind_request()
        if resp is None: 
            return "NO CONNECTIVITY"
