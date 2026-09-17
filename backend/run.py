"""
Entry-point for local development on Windows.

uvicorn --reload spawns a child process whose event loop is created *before*
the app module is imported, so the WindowsProactorEventLoopPolicy set inside
main.py is too late for Playwright (which needs subprocess support).

Running via this script instead of `uvicorn app.main:app --reload` sets the
policy *before* uvicorn creates its event loop, which fixes the
NotImplementedError when Playwright tries to launch Chromium on Windows.
"""

import sys
import asyncio

# Must be done before uvicorn imports anything that touches the event loop.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,           # hot-reload still works
        loop="asyncio",        # explicitly use ProactorEventLoop on Windows
    )
