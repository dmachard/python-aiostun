import aiostun
import asyncio

# list of online server

# stun.ekiga.net 3478 UDP
# stun.nextcloud.com 3478;443 UDP;TCP
# stun.l.google.com;stun[1-2-3-4].l.google.com 19302 UDP IP4;IP6
# openrelay.metered.ca 80;443 UDP;TCP;TLS IP4
# stun.stunprotocol.org 3478 UDP;TCP IP4;IP6
# relay.webwormhole.io 3478 UDP;TCP IP4;IP6
# turns.goog 443 TLS IP4;IP6
# turn.goog 3478 UDP;TCP IP4;IP6
# global.turn.twilio.com 3478;443 UDP;TCP IP4
# turn.matrix.org 3478;443 UDP;TCP;TLS IP4;IP6
# turn.fairmeeting.net 443;5349 UDP;TLS IP4;IP6
# stun.incentre.net 3478;5349 UDP;TCP;TLS IP4

async def main():

    async with aiostun.Client(host="turn.matrix.org", port=3478, family=aiostun.IP4, proto=aiostun.UDP) as stunc:
        mapped_addr = await stunc.get_mapped_address()
        print(mapped_addr)

        stun_req = aiostun.Message(msgclass=aiostun.CLASS_REQUEST, 
                                    msgmethod=2, #aiostun.METHOD_BINDING,
                                    attrs=[
                                        #aiostun.AttrRealm(value="hello"),
                                        # aiostun.AttrUsername(value="world"),
                                        # aiostun.AttrSoftware(value="aiostun")
                                    ])

        success = stunc.send_request(stun_req)
        resp = await stunc.wait_for_resp()
        print(resp)

asyncio.run(main())