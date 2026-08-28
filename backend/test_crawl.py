import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

async def test():
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        r = await client.get("http://testphp.vulnweb.com/")
        print("Status:", r.status_code)
        print("Content-Type:", r.headers.get("content-type"))
        print("URL:", str(r.url))

asyncio.run(test())
