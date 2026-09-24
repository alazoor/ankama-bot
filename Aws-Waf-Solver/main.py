import asyncio
import sys ; sys.dont_write_bytecode= True;
from waf.solver import solve

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"

async def main():
    result, _ = await solve("https://www.booking.com", UA)
    print(result)

asyncio.run(main())
