import aiostun
import asyncio

# stun.ekiga.net 3478 UDP
# stun.nextcloud.com 3478 UDP;TCP
# stun.l.google.com; stun2.l.google.com19302 UDP IP4;IP6
# openrelay.metered.ca 80;443 UDP;TCP;TLS IP4;IP6
# stun.stunprotocol.org 3478 UDP;TCP IP4;IP6
# relay.webwormhole.io 3478 UDP;TCP IP4;IP6
# turns.goog 443 TLS IP4;IP6
# turn.goog 3478 UDP;TCP IP4;IP6

async def main():

    stun_host = "52.114.249.120"
    stun_port = 3478
    stun_family = aiostun.FAMILY_IP4
    stun_proto = aiostun.IPPROTO_UDP

    async with aiostun.Client(host=stun_host, port=stun_port, family=stun_family, ipproto=stun_proto) as stunc:
        #mapped_addr = await stunc.get_mapped_address()
        #print(mapped_addr)
        
        resp = await stunc.bind_request()
        print(resp)

asyncio.run(main())