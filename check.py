import sys
import asyncio


def usage():
    print('usage: python3 check.py config ip')
    exit()


if len(sys.argv) < 3:
    usage()


from antissh import fetch_banner, check_with_credentials_shallow, TARGET_IP, TARGET_PORT


def main():
    ip = sys.argv[2]

    print('checking', ip)
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(check_with_credentials_shallow(ip, TARGET_IP, TARGET_PORT))
    print('result:', result)


if __name__ == '__main__':
    main()
