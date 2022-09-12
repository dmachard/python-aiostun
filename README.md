# Async STUN client for Python

## Key Features

- [x] Support RFC3489
- [x] Transports UDP, TCP and TLS
- [x] IPv4 and IPv6 support
- [ ] Support RFC5389
- [ ] Support RFC5780
- [ ] Support RFC8489

## Installation

This module can be installed from [pypi](https://pypi.org/project/aiostun/) website

```python
pip install aiostun
```

## Getting your mapped address

```python
import aiostun
import asyncio

async def main():

    async with aiostun.Client(host='openrelay.metered.ca', port=443, ipproto=aiostun.TLS) as stunc:
        mapped_addr = await stunc.get_mapped_address()
        print(mapped_addr)
        {'family': 'IPv4', 'port': 38778, 'ip': 'xx.xx.xx.xx'}

asyncio.run(main())
```

## For developers

Running all test units.

```bash
python3 -m unittest discover tests/ -v
```