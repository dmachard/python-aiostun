
from aiostun import client
from aiostun import constants
from aiostun import attribute

NETWORK_ERROR = "Network Error"
PROTOCOL_ERROR = "Protocol Error"
OPEN_INTERNET = "Open Internet"
SYMMETRIC_UDP_FIREWALL = "Symmetric Udp Firewall"
FULL_CONE = "Full Cone"
SYMMETRIC_NAT = "Symmetric NAT"
RESTRICTED_NAT = "Restricted NAT"
RESTRICTED_PORT_NAT = "Restricted Port NAT"

class NAT:
    __DEFAULT_STUN_HOST__ = "turn.matrix.org"
    __DEFAULT_STUN_PORT__ = 3478
    async def discover(self, use_classicstun=False, **kwargs):
        """Discovery NAT"""
        if use_classicstun:
            return await self.classic_discover(**kwargs)

        raise Exception("Not yet implemented")

    async def classic_discover(self, stun_host=__DEFAULT_STUN_HOST__, stun_port=__DEFAULT_STUN_PORT__):
        """discover like described in the rfc3489"""
        nat_behavior = {}
        use_classicstun = True

        # Test I: the client sends a STUN Binding Request to a server,
        # without any flags set in the CHANGE-REQUEST attribute,
        # and without the RESPONSE-ADDRESS attribute.
        stun_test = client.Client(host=stun_host, port=stun_port,
                                  family=constants.FAMILY_IP4,
                                  proto=constants.IPPROTO_UDP)
        # connect and get the local ip and port
        await stun_test.connect(remote_addr=False)

        # Send bind request without any flag
        # if no response, the reason can be multiple: UDP blocked ? network issue ? or the server is down ?
        resp_test1 = await stun_test.bind_request(use_classicstun=use_classicstun, remote_addr=(stun_host, stun_port))
        if resp_test1 is None:
           nat_behavior["error"] = NETWORK_ERROR
           return nat_behavior

        # read local port
        (local_ipI, local_portI) = stun_test.get_local_addr()
        nat_behavior["local-ip"] = local_ipI
        nat_behavior["local-port"] = local_portI

        # if the mapped addr  and changed addr is missing, something is wrong
        mappedAddr = resp_test1.get_attribute(attribute.AttrMappedAddr)
        nat_behavior["external-ip"] = mappedAddr.params["ip"]
        nat_behavior["external-port"] = mappedAddr.params["port"]

        changedaddr = resp_test1.get_attribute(attribute.AttrChangedAddress)
        if mappedAddr is None:
            nat_behavior["error"] = PROTOCOL_ERROR
            return nat_behavior
        if changedaddr is None:
            nat_behavior["error"] = PROTOCOL_ERROR
            return nat_behavior

        # Test II: the client sends a Binding Request with both the "change IP" and "change port" flags
        # from the CHANGE-REQUEST attribute set
        attr_changereq = attribute.AttrChangeRequest(changeIp=True, changePort=True)
        resp_test2 = await stun_test.bind_request(use_classicstun=use_classicstun,
                                                  attrs=[attr_changereq],
                                                  remote_addr=(stun_host, stun_port))

        if mappedAddr.params["ip"] == local_ipI and resp_test2 is None:
            nat_behavior["nat"] = SYMMETRIC_UDP_FIREWALL
            return nat_behavior

        if mappedAddr.params["ip"] == local_ipI and resp_test2:
            nat_behavior["nat"] = OPEN_INTERNET
            return nat_behavior

        if mappedAddr.params["ip"] != local_ipI and resp_test2:
            nat_behavior["nat"] = FULL_CONE
            return nat_behavior

        # Test I Again:  but this time, does to the address and port from the CHANGED-ADDRESS attribute
        # from initial binding request
        if mappedAddr.params["ip"] != local_ipI and resp_test2 is None:

            remote_addr = (changedaddr.params["ip"], changedaddr.params["port"])
            resp_test1_again = await stun_test.bind_request(use_classicstun=use_classicstun,
                                                            attrs=[], remote_addr=remote_addr)
            if resp_test1_again is None:
                nat_behavior["error"] = PROTOCOL_ERROR
                return nat_behavior

            mappedAddr_again = resp_test1_again.get_attribute(attribute.AttrMappedAddr)
            if mappedAddr_again is None:
                nat_behavior["error"] = PROTOCOL_ERROR
                return nat_behavior

            if not (mappedAddr_again.params["ip"] == mappedAddr.params["ip"] and mappedAddr_again.params["port"] == mappedAddr.params["port"]):
                nat_behavior["nat"] = SYMMETRIC_NAT
                return nat_behavior

            # Test III: the client sends a Binding Request with only the "change port" flag set.
            attr_changereq3 = attribute.AttrChangeRequest(changeIp=False, changePort=True)
            remote_addr = (changedaddr.params["ip"], changedaddr.params["port"])
            resp_test3 = await stun_test.bind_request(use_classicstun=use_classicstun,
                                                      attrs=[attr_changereq3],
                                                      remote_addr=remote_addr)
            if resp_test3:
                nat_behavior["nat"] = RESTRICTED_NAT
                return nat_behavior
            else:
                nat_behavior["nat"] = RESTRICTED_PORT_NAT
                return nat_behavior
