import aiostun
import asyncio

async def main():
    behavenat = aiostun.NAT()
    behavior = await behavenat.discover(use_classicstun=True)
    print(behavior)

asyncio.run(main())