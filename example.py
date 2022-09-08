import aiostun
import asyncio

# stun.ekiga.net 3478 UDP
# stun.nextcloud.com 3478 UDP;TCP
# stun.l.google.com;stun[1-2-3-4].l.google.com 19302 UDP IP4;IP6
# openrelay.metered.ca 80;443 UDP;TCP;TLS IP4;IP6
# stun.stunprotocol.org 3478 UDP;TCP IP4;IP6
# relay.webwormhole.io 3478 UDP;TCP IP4;IP6
# turns.goog 443 TLS IP4;IP6
# turn.goog 3478 UDP;TCP IP4;IP6
# global.turn.twilio.com 3478;443 UDP;TCP IP4
# turn.matrix.org 3478;443 UDP;TCP;TLS IP4;IP6
# turn.fairmeeting.net 443;5349 UDP;TLS IP4;IP6
# stun.incentre.net 3478;5349 UDP;TCP;TLS IP4

async def main():

    stun_host = "stun.incentre.net"
    stun_port = 443
    stun_family = aiostun.FAMILY_IP4
    stun_proto = aiostun.IPPROTO_TLS

    async with aiostun.Client(host=stun_host, port=stun_port, family=stun_family, ipproto=stun_proto) as stunc:
        #mapped_addr = await stunc.get_mapped_address()
        #print(mapped_addr)
        
        resp = await stunc.bind_request()
        print(resp)

asyncio.run(main())