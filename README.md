# Async STUN client for Python

## Key Features

- Support RFC5389/RFC8489
- Transports UDP, TCP and TLS
- IPv4 and IPv6 support

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