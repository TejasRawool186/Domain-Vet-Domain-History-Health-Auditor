"""
__main__.py - Standard package entrypoint for Apify Python Actor.
"""
import asyncio
import os
import sys

# Ensure src directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import main

if __name__ == '__main__':
    asyncio.run(main())

