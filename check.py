import sys
import asyncio


def usage():
    print('usage: python3 check.py config ip username password')
    exit()


if len(sys.argv) < 5:
    usage()


from antissh import check_with_credentials, TARGET_IP, TARGET_PORT


def main():
    ip = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]

    print('checking', ip)
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(check_with_credentials(ip, TARGET_IP, TARGET_PORT, username, password))

    print('result:', result)


if __name__ == '__main__':
    main()
