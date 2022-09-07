import struct
import asyncio
import string
import random

from aiostun import constants
from aiostun import attribute

def gen_id(length=12):
    """generate random id"""
    chars = string.ascii_lowercase
    chars += string.ascii_uppercase
    return b''.join([random.choice(chars).encode() for i in range(length)])

class StunMessage():
    def __init__(self, msgclass, msgmethod):
        """init"""
        self.msglength = 0
        self.msgmethod = msgmethod
        self.msgclass = msgclass
        self.magic_cookie = constants.MAGIC_COOKIE
        self.transaction_id = gen_id()
        self.attributes = []

    def get_class(self):
        """return class name"""
        return constants.CLASS_NAMES[self.msgclass]

    def get_method(self):
        """return method name"""
        return constants.METHOD_NAMES[self.msgmethod]

    def get_attribute(self, atype):
        """get attribute"""
        for attr in self.attributes:
            if isinstance(attr, atype):
                return attr
        return None

    def decode_attrs(self, attrs):
        """decode all attributes"""
        for attr in attrs:
            attr_obj = None

            if attr["type"] in [ constants.ATTR_XOR_MAPPED_ADDRESS, constants.ATTR_XOR_MAPPED_ADDRESS_OPTIONAL ]:
                attr_obj = attribute.XorMappedAddr(self, attr["type"], attr["value"])

            elif attr["type"] == constants.ATTR_MAPPED_ADDRESS:
                attr_obj = attribute.MappedAddr(self, attr["type"], attr["value"])

            elif attr["type"] == constants.ATTR_SOFTWARE:
                attr_obj = attribute.Software(self, attr["type"], attr["value"])

            elif attr["type"] == constants.ATTR_OTHER_ADDRESS:
                attr_obj = attribute.OtherAddress(self, attr["type"], attr["value"])

            elif attr["type"] == constants.ATTR_RESPONSE_ORIGIN:
                attr_obj = attribute.ResponseOrigin(self, attr["type"], attr["value"])

            elif attr["type"] == constants.ATTR_FINGERPRINT:
                attr_obj = attribute.Fingerprint(self, attr["type"], attr["value"])

            elif attr["type"] == constants.ATTR_SOURCE_ADDRESS:
                attr_obj = attribute.SourceAddress(self, attr["type"], attr["value"])
            
            elif attr["type"] == constants.ATTR_CHANGED_ADDRESS:
                attr_obj = attribute.ChangedAddress(self, attr["type"], attr["value"])

            else:
                attr_obj = attribute.Attribute(self, attr["type"], attr["value"])

            if attr_obj is not None:
                self.attributes.append(attr_obj)

    def get_length(self):
        """return length of the message"""
        return 0

    def __str__(self):
        """to string representation"""
        ret = ["Header:"]
        ret.append("\tMessage Type: %s %s" % (constants.CLASS_NAMES[self.msgclass], constants.METHOD_NAMES[self.msgmethod]))
        ret.append("\tMessage Length: %s" % self.msglength)
        ret.append("\tMessage TransactionID: %s" % self.transaction_id.decode())

        if len(self.attributes):
            ret.append("Attributes:")
            for attr in self.attributes:
                ret.append("\t%s" % attr)
            #ret.append("")

        return "\n".join(ret)

class Codec:
    def __init__(self):
        """init"""
        self.buf = b""
        self._queue = asyncio.Queue(0)

    def feed_data(self, data):
        """append data to the buffer"""
        self.buf = b''.join([self.buf, data])

        resp = self.decode()
        if resp is None: return

        self._queue.put_nowait(resp)

    def decode(self):
        """decode data from buffer"""
        if len(self.buf) < constants.STUN_HEADER_SIZE:
            return None

        # enough data to decode header
        (stunlength,) = struct.unpack("!H", self.buf[2:4])

        if len(self.buf) < stunlength + constants.STUN_HEADER_SIZE:
            return None

        # decode header
        (stuntype, stunlength) = struct.unpack("!HH", self.buf[:4])

        # remote packet from buffer
        pl = self.buf[:stunlength+constants.STUN_HEADER_SIZE]
        self.buf = self.buf[stunlength+constants.STUN_HEADER_SIZE:]

        # decode class and method
        stunclass = ((stuntype & 0x0010) >> 4) | ((stuntype & 0x0100) >> 7)
        stunmethod = (stuntype & 0x000F) | ((stuntype & 0x00E0) >> 1)  | ((stuntype & 0x3E00) >> 2)

        # read magic cookie and transactionid
        (magic_cookie,) = struct.unpack("!L", pl[4:8])
        (transaction_id,) = struct.unpack("!12s", pl[8:20])

        # finally, decode attributes
        pl = pl[20:]
        attrs = []
        while len(pl) >= 4:
            # read attribute
            (attr_type, attr_length,) = struct.unpack("!HH", pl[:4])

            # padding ?
            pad_length = ((attr_length+4) % 4)

            attrs.append( {"type": attr_type, "value": pl[4:4+attr_length]} )

            # data remaining for next attributes
            pl = pl[4+attr_length+pad_length:]

        rsp = StunMessage(stunclass, stunmethod)
        rsp.msglength = stunlength
        rsp.magic_cookie = magic_cookie
        rsp.transaction_id = transaction_id
        rsp.decode_attrs(attrs)

        return rsp

    def encode(self, m):
        """encode the stun message"""
        # add message class and method
        stuntype = (((m.msgclass & 0x02) << 7) | ((m.msgclass & 0x01) << 4)) | m.msgmethod & 0x3EEF
        buf = struct.pack("!H", stuntype)

        # append message size
        buf += struct.pack("!H", m.get_length())
        buf += struct.pack("!L", m.magic_cookie)
        buf += struct.pack("!12s", m.transaction_id)

        return buf
        pass

