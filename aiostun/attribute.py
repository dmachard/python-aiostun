import struct
import ipaddress

from aiostun import constants

class Attribute:
    def __init__(self, attr_type):
        """init"""
        self.attr_type = attr_type
        self.params = {}

    def get_name(self):
        """return class name"""
        if self.attr_type in constants.ATTR_NAMES:
            return constants.ATTR_NAMES[self.attr_type]
        return "%s (Unknown)" % self.attr_type

    def __str__(self):
        """sting representation"""
        ret = [ self.get_name() ]
        for l in self.to_string():
            ret.append( "\t* %s" % l )
        return "\n".join(ret)

    def decode(self, value):
        """decode the value of the attribute"""
        self.params["value"] = value

    def encode(self):
        """to bytes"""
        return self.params["value"]

    def to_string(self):
        """human string representation"""
        return [ "%s" % self.params["value"] ]

# https://www.rfc-editor.org/rfc/rfc3489#section-11.2.1
# 0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |x x x x x x x x|    Family     |           Port                |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             Address                           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
class AttributeAddr(Attribute):
    def to_string(self):
        """human string representation"""
        ret = [ "Protocol Family: %s" % self.params["family"] ]
        ret.append( "IP: %s" % self.params["ip"] )
        ret.append( "Port: %s" % self.params["port"] )
        return ret

    def decode(self, value):
        """decode the attribute"""
        # read family protocol, ipv4 (1) or ipv6 (2)
        (family,) = struct.unpack("!B", value[1:2])
        if family > 0x02 and family < 0x01:
            return False

        # decode port and ip
        (port,) = struct.unpack("!H", value[2:4])
        if family == 0x01:
            ip = "%s" % ipaddress.IPv4Address(value[4:])
        if family == 0x02:
            ip = "%s" % ipaddress.IPv6Address(value[4:])

        self.params["family"] = constants.FAMILY_NAMES[family]
        self.params["port"] = port
        self.params["ip"] = ip

class AttributeStr(Attribute):
    def __init__(self, attr_type, attr_value):
        Attribute.__init__(self, attr_type)
        self.params["value"] = attr_value
    def to_string(self):
        r = self.params["value"]
        r = "%s" % r if isinstance(r, str) else "%s" % r.decode()
        return [ r ]
    def encode(self):
        r = self.params["value"]
        return r.encode() if isinstance(r, str) else r
        

class XorMappedAddrAttribute(Attribute):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_XOR_MAPPED_ADDRESS)
    def to_string(self):
        """human string representation"""
        ret = [ "Protocol Family: %s" % self.params["family"] ]
        ret.append( "IP: %s" % self.params["ip"] )
        ret.append( "Port: %s" % self.params["port"] )
        return ret

    def decode(self, value, tid):
        """decode the attribute"""
        # read family protocol, ipv4 (1) or ipv6 (2)
        (family,) = struct.unpack("!B", value[1:2])
        if family > 0x02 and family < 0x01:
            return False

        # decode port
        (port_xor,) = struct.unpack("!H", value[2:4])
        port = port_xor ^ (constants.MAGIC_COOKIE >> 16)

        # prepare key for xor
        if family == 0x01:
            key = struct.pack("!L", constants.MAGIC_COOKIE)
        if family == 0x02:
            key = struct.pack("!L", constants.MAGIC_COOKIE)
            key += struct.pack("!12s", tid)

        # decode ip
        host = bytes(a ^ b for a, b in zip(value[4:], key))
        if family == 0x01:
            ip = "%s" % ipaddress.IPv4Address(host)
        if family == 0x02:
            ip = "%s" % ipaddress.IPv6Address(host)

        self.params["family"] = constants.FAMILY_NAMES[family]
        self.params["port"] = port
        self.params["ip"] = ip

# basic address (ip/port) attributes
class MappedAddrAttribute(AttributeAddr):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_MAPPED_ADDRESS)
class OtherAddressAttribute(AttributeAddr):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_OTHER_ADDRESS)
class ResponseOriginAttribute(AttributeAddr):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_RESPONSE_ORIGIN)
class SourceAddressAttribute(AttributeAddr):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_SOURCE_ADDRESS)
class ChangedAddressAttribute(AttributeAddr):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_CHANGED_ADDRESS)

# https://www.rfc-editor.org/rfc/rfc3489#section-11.2.9
# 0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                   0                     |Class|     Number    |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |      Reason Phrase (variable)                                ..
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
class ErrorCodeAttribute(Attribute):
    def __init__(self):
        Attribute.__init__(self, attr_type=constants.ATTR_ERROR_CODE)

    def to_string(self):
        ret = [ "Code: %s" % self.params["code"] ]
        ret.append( "Phrase: %s" % self.params["phrase"])
        return ret

    def decode(self, value):
        err_code = value[2]*100 + value[3]
        err_phrase = value[4:].decode()
        self.params["code"] = err_code
        self.params["phrase"] = err_phrase


# https://www.rfc-editor.org/rfc/rfc3489#section-11.2.8
class AttrIntegrity(AttributeStr):
    def __init__(self, value):
        AttributeStr.__init__(self, attr_type=constants.ATTR_MESSAGE_INTEGRITY, attr_value=value)
    def to_string(self):
         return [ "0x%s" % self.params["value"].hex() ]
class AttrFingerPrint(AttributeStr):
    def __init__(self, value):
        AttributeStr.__init__(self, attr_type=constants.ATTR_FINGERPRINT, attr_value=value)
    def to_string(self):
         return [ "0x%s" % self.params["value"].hex() ]

class AttrNonce(AttributeStr):
    def __init__(self, value):
        AttributeStr.__init__(self, attr_type=constants.ATTR_NONCE, attr_value=value)

class AttrSoftware(AttributeStr):
    def __init__(self, value):
        AttributeStr.__init__(self, attr_type=constants.ATTR_SOFTWARE, attr_value=value)

class AttrRealm(AttributeStr):
    def __init__(self, value):
        AttributeStr.__init__(self, attr_type=constants.ATTR_REALM, attr_value=value)

class AttrUsername(AttributeStr):
    def __init__(self, value):
        AttributeStr.__init__(self, attr_type=constants.ATTR_USERNAME, attr_value=value)
