#!/usr/bin/env python3

"""Perform a shallow test against a single target."""

import sys
import asyncio
from antissh import check_with_credentials_shallow, TARGET_IP, TARGET_PORT


def usage():
    """Print an error message explaining the expected use and exit."""
    print('usage: python3 check.py config ip')
    exit()


def main():
    """CLI entry point for antissh.check."""
    if len(sys.argv) < 3:
        usage()

    address = sys.argv[2]

    print('checking', address)
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(
        check_with_credentials_shallow(address, TARGET_IP, TARGET_PORT))
    print('result:', result)


if __name__ == '__main__':
    main()
