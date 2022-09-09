import struct
import ipaddress

from aiostun import constants


class Attribute:
    def __init__(self, msg_hdr, attr_type, attr_value):
        """init"""
        self.attr_type = attr_type
        self.attr_value = attr_value
        self.msg_hdr = msg_hdr
        self.params = {}

        self.decode()

    def __str__(self):
        """sting representation"""
        ret = [ constants.ATTR_NAMES[self.attr_type] ]
        for l in self.to_string():
            ret.append( "\t\t%s" % l )
        return "\n".join(ret)

    def decode(self):
        """decode the value of the attribute"""
        pass

    def to_string(self):
        """human string representation"""
        return [ "%s" % self.attr_value ]

class XorMappedAddr(Attribute):
    def to_string(self):
        """human string representation"""
        ret = [ "Protocol Family: %s" % self.params["family"] ]
        ret.append( "IP: %s" % self.params["ip"] )
        ret.append( "Port: %s" % self.params["port"] )
        return ret

    def decode(self):
        """decode the attribute"""
        # read family protocol, ipv4 (1) or ipv6 (2)
        (family,) = struct.unpack("!B", self.attr_value[1:2])
        if family > 0x02 and family < 0x01:
            return False

        # decode port
        (port_xor,) = struct.unpack("!H", self.attr_value[2:4])
        port = port_xor ^ (self.msg_hdr.magic_cookie >> 16)

        # prepare key for xor
        if family == 0x01:
            key = struct.pack("!L", self.msg_hdr.magic_cookie)
        if family == 0x02:
            key = struct.pack("!L", self.msg_hdr.magic_cookie)
            key += struct.pack("!12s", self.msg_hdr.transaction_id)

        # decode ip
        host = bytes(a ^ b for a, b in zip(self.attr_value[4:], key))
        if family == 0x01:
            ip = "%s" % ipaddress.IPv4Address(host)
        if family == 0x02:
            ip = "%s" % ipaddress.IPv6Address(host)

        self.params["family"] = constants.FAMILY_NAMES[family]
        self.params["port"] = port
        self.params["ip"] = ip

class AttributeAddr(Attribute):
    def to_string(self):
        """human string representation"""
        ret = [ "Protocol Family: %s" % self.params["family"] ]
        ret.append( "IP: %s" % self.params["ip"] )
        ret.append( "Port: %s" % self.params["port"] )
        return ret

    def decode(self):
        """decode the attribute"""
        # read family protocol, ipv4 (1) or ipv6 (2)
        (family,) = struct.unpack("!B", self.attr_value[1:2])
        if family > 0x02 and family < 0x01:
            return False

        # decode port and ip
        (port,) = struct.unpack("!H", self.attr_value[2:4])
        if family == 0x01:
            ip = "%s" % ipaddress.IPv4Address(self.attr_value[4:])
        if family == 0x02:
            ip = "%s" % ipaddress.IPv6Address(self.attr_value[4:])

        self.params["family"] = constants.FAMILY_NAMES[family]
        self.params["port"] = port
        self.params["ip"] = ip

class MappedAddr(AttributeAddr): pass
class OtherAddress(AttributeAddr): pass
class ResponseOrigin(AttributeAddr): pass
class SourceAddress(AttributeAddr): pass
class ChangedAddress(AttributeAddr): pass

class Software(Attribute):
    def to_string(self):
        return [ "Description: %s" % self.params["description"] ]
    def decode(self):
        self.params["description"] = self.attr_value.decode()

class Fingerprint(Attribute):
    def to_string(self):
        return [ "CRC-32: 0x%s" % self.params["crc32"].hex() ]
    def decode(self):
        self.params["crc32"] = self.attr_value

class ErrorCode(Attribute):
    def to_string(self):
        ret = [ "Code: %s" % self.params["code"] ]
        ret.append( "Phrase: %s" % self.params["phrase"])
        return ret

    def decode(self):
        err_code = self.attr_value[2]*100 + self.attr_value[3]
        err_phrase = self.attr_value[4:].decode()
        self.params["code"] = err_code
        self.params["phrase"] = err_phrase

class Nonce(Attribute):
    def to_string(self):
        return [ "Nonce: 0x%s" % self.params["nonce"].decode()]
    def decode(self):
        self.params["nonce"] = self.attr_value

class Realm(Attribute):
    def to_string(self):
        return [ "Realm: %s" % self.params["realm"] ]
    def decode(self):
        self.params["realm"] = self.attr_value.decode()

SUPPORTED_ATTRS = {
    constants.ATTR_XOR_MAPPED_ADDRESS: XorMappedAddr,
    constants.ATTR_XOR_MAPPED_ADDRESS_OPTIONAL: XorMappedAddr,
    constants.ATTR_MAPPED_ADDRESS: MappedAddr,
    constants.ATTR_OTHER_ADDRESS: OtherAddress,
    constants.ATTR_RESPONSE_ORIGIN: ResponseOrigin,
    constants.ATTR_SOURCE_ADDRESS: SourceAddress,
    constants.ATTR_CHANGED_ADDRESS: ChangedAddress,
    constants.ATTR_SOFTWARE: Software,
    constants.ATTR_FINGERPRINT: Fingerprint,
    constants.ATTR_ERROR_CODE: ErrorCode,
    constants.ATTR_NONCE: Nonce,
    constants.ATTR_REALM: Realm,
}

def get(msg_hdr, attr_type, attr_value):
    return SUPPORTED_ATTRS[attr_type](msg_hdr, attr_type, attr_value)