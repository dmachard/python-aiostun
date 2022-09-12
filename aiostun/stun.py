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

class Message(object):
    def __init__(self, msgclass, msgmethod, attrs):
        """init"""
        self.msglength = 0
        self.msgmethod = msgmethod
        self.msgclass = msgclass
        self.magic_cookie = constants.MAGIC_COOKIE
        self.transaction_id = gen_id()
        self.attributes = attrs

    def get_class(self):
        """return class name"""
        if self.msgclass in constants.CLASS_NAMES:
            return constants.CLASS_NAMES[self.msgclass]
        return "%s (Unsupported)" % self.msgclass

    def get_method(self):
        """return method name"""
        if self.msgmethod in constants.METHOD_NAMES:
            return constants.METHOD_NAMES[self.msgmethod]
        return "%s (Unsupported)" % self.msgmethod

    def get_attribute(self, atype):
        """get attribute"""
        for attr in self.attributes:
            if isinstance(attr, atype):
                return attr
        return None

    def decode_attrs(self, attrs):
        """decode all attributes"""
        for attr in attrs:
            # decode the value 
            if attr["type"] in [ constants.ATTR_XOR_MAPPED_ADDRESS, constants.ATTR_XOR_MAPPED_ADDRESS_OPTIONAL ]:
                attr_obj = attribute.XorMappedAddrAttribute()
                attr_obj.decode(value=attr["value"], tid=self.transaction_id)
                
            elif attr["type"] in [ constants.ATTR_MAPPED_ADDRESS ]:
                attr_obj = attribute.MappedAddrAttribute()
                attr_obj.decode(value=attr["value"])

            elif attr["type"] in [ constants.ATTR_OTHER_ADDRESS ]:
                attr_obj = attribute.OtherAddressAttribute()
                attr_obj.decode(value=attr["value"])

            elif attr["type"] in [ constants.ATTR_RESPONSE_ORIGIN ]:
                attr_obj = attribute.ResponseOriginAttribute()
                attr_obj.decode(value=attr["value"])

            elif attr["type"] in [ constants.ATTR_SOURCE_ADDRESS ]:
                attr_obj = attribute.SourceAddressAttribute()
                attr_obj.decode(value=attr["value"])

            elif attr["type"] in [ constants.ATTR_CHANGED_ADDRESS ]:
                attr_obj = attribute.ChangedAddressAttribute()
                attr_obj.decode(value=attr["value"])

            elif attr["type"] in [ constants.ATTR_SOFTWARE ]:
                attr_obj = attribute.AttrSoftware(attr["value"])

            elif attr["type"] in [ constants.ATTR_FINGERPRINT ]:
                attr_obj = attribute.AttrFingerPrint(attr["value"])

            elif attr["type"] in [ constants.ATTR_ERROR_CODE ]:
                attr_obj = attribute.ErrorCodeAttribute()
                attr_obj.decode(value=attr["value"])

            elif attr["type"] in [ constants.ATTR_NONCE ]:
                attr_obj = attribute.AttrNonce(attr["value"])

            elif attr["type"] in [ constants.ATTR_REALM ]:
                attr_obj = attribute.AttrRealm(attr["value"])

            else:
                print(attr["type"], attr["value"])
                attr_obj = attribute.Attribute(attr["type"])
                attr_obj.decode(value=attr["value"])

            # append to the list
            self.attributes.append(attr_obj)

    def __str__(self):
        """to string representation"""
        ret = ["Header:"]
        ret.append("\tMessage Type:")
        ret.append("\t\tClass: %s" % self.get_class())
        ret.append("\t\tMethod: %s" % self.get_method())
        ret.append("\tMessage Length: %s" % self.msglength)
        ret.append("\tMessage TransactionID: %s" % self.transaction_id.decode())

        if len(self.attributes):
            ret.append("Attributes:")
            for attr in self.attributes:
                ret.append("\t%s" % attr)
            #ret.append("")

        return "\n".join(ret)

class ClassicMessage(Message):
    def __init__(self, msgclass, msgmethod, attrs):
        Message.__init__(self, msgclass, msgmethod, attrs)
        self.magic_cookie = 0
        self.transaction_id = gen_id(length=16)

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
        if magic_cookie != constants.MAGIC_COOKIE:
            magic_cookie = 0
            (transaction_id,) = struct.unpack("!16s", pl[4:20])
        else:
            (transaction_id,) = struct.unpack("!12s", pl[8:20])

        # finally, decode attributes
        pl = pl[20:]
        attrs = []
        while len(pl) >= 4:
            # read attribute
            (attr_type, attr_length,) = struct.unpack("!HH", pl[:4])

            # padding ? always a multiple of 4 bytes
            pad_mod = 4-((attr_length+4) % 4)
            pad_length = 0 if pad_mod == 4 else pad_mod

            attrs.append( {"type": attr_type, "value": pl[4:4+attr_length]} )

            # data remaining for next attributes
            pl = pl[4+attr_length+pad_length:]

        rsp = Message(stunclass, stunmethod, [])
        rsp.msglength = stunlength
        rsp.magic_cookie = magic_cookie
        rsp.transaction_id = transaction_id
        rsp.decode_attrs(attrs)

        return rsp

    def encode(self, m):
        """encode the stun message"""
        # encode attributes
        msg_attr = b""
        # attrib
        for cur_attr in m.attributes:
            attr_value = cur_attr.encode()
            data_attr =  struct.pack("!HH", cur_attr.attr_type, len(attr_value))
            data_attr += attr_value

            # padding ?
            while 4-(len(data_attr)% 4) != 4:
                data_attr += b"\x00"*(4-(len(data_attr)% 4))
            msg_attr += data_attr

        attr_length = len(msg_attr)

        # add message class and method
        stuntype = (((m.msgclass & 0x02) << 7) | ((m.msgclass & 0x01) << 4)) | m.msgmethod & 0x3EEF
        buf = struct.pack("!H", stuntype)

        # append message size
        buf += struct.pack("!H", attr_length)
        if m.magic_cookie > 0:
            buf += struct.pack("!L", m.magic_cookie)
            buf += struct.pack("!12s", m.transaction_id)
        else:
            buf += struct.pack("!16s", m.transaction_id)

        # append attributes
        buf += msg_attr

        return buf

    def send(self, data):
        """send data"""
        pass