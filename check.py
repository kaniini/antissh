import sys
import asyncio
from antissh import check_with_credentials_shallow, TARGET_IP, TARGET_PORT


def usage():
    print('usage: python3 check.py config ip')
    exit()


def main():
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
