#!/usr/bin/env python3
# dependencies: asyncssh, asyncio-irc

import asyncio
import asyncssh
import sys
import re
import aiohttp
import json
from asyncirc import irc
from configparser import ConfigParser
import logging

config = ConfigParser()
config.read(sys.argv[1])

TARGET_IP = config.get('target', 'ip', fallback='162.220.112.99')
TARGET_PORT = config.getint('target', 'port', fallback=6667)
QUICK_MODE = config.getboolean('target', 'quick_mode', fallback=False)
HOST = config.get('host', 'hostname', fallback='irc.dereferenced.org')
PORT = config.getint('host', 'port', fallback=6667)
USE_SSL = config.getboolean('host', 'ssl', fallback=False)
OPER = config.get('host', 'oper', fallback='x x')
NICKNAME = config.get('host', 'nickname', fallback='antissh')
MODES = config.get('host', 'modes', fallback='')
KLINE_CMD_TEMPLATE = config.get('host', 'kline_cmd', fallback='KLINE 86400 *@{ip} :Vulnerable SSH daemon found on this host.  Please fix your SSH daemon and try again later.\r\n')

# advanced users only
# charybdis uses:
# *** Notice -- Client connecting: kaniini_ (~kaniini@127.0.0.1) [127.0.0.1] {users} [William Pitcock]
# re.findall(r'\[[0-9a-f\.:]+\]', message)
IP_REGEX = re.compile(r'Client connecting\:.*\[([0-9a-f\.:]+)\]')
POSITIVE_HIT_STRING = b'Looking up your hostname'
DEFAULT_CREDENTIALS = [
    ('ADMIN', 'ADMIN'),
    ('admin', '123456'),
    ('admin', ''),
    ('root', ''),
    ('root', 'admin')
]

# dnsbl settings
dronebl_key = config.get('dnsbl', 'dronebl_key', fallback=None)
dnsbl_im_key = config.get('dnsbl', 'dnsbl_im_key', fallback=None)
dnsbl_active = (dronebl_key is not None or dnsbl_im_key is not None)


async def submit_dronebl(ip):
    add_stanza = '<add ip="{ip}" type="15" port="22" comment="{comment}" />'.format(
        ip=ip, comment='A vulnerable SSH server on an IOT gateway, detected by antissh.')
    envelope = '<?xml version="1.0"?><request key="{key}">{stanza}</request>'.format(
        key=dronebl_key, stanza=add_stanza)
    headers = {
        'Content-Type': 'text/xml'
    }

    async with aiohttp.ClientSession() as session:
        await session.post('https://dronebl.org/rpc2', headers=headers, data=envelope)


async def submit_dnsbl_im(ip):
    envelope = {
        'key': dnsbl_im_key,
        'addresses': [{
            'ip': ip,
            'type': '4',
            'reason': 'A vulnerable SSH server on an IOT gateway, detected by antissh.'
        }]
    }
    headers = {
        'Content-Type': 'application/json'
    }

    async with aiohttp.ClientSession() as session:
        await session.post('https://api.dnsbl.im/import', headers=headers, data=json.dumps(envelope))


async def check_with_credentials(ip, target_ip, target_port, username, password):
    """Checks whether a given username or password works to open a direct TCP session."""
    try:
        async with asyncssh.connect(
                ip, username=username, password=password,
                known_hosts=None, client_keys=None, client_host_keys=None,
                agent_path=None) as conn:
            if QUICK_MODE:
                return True
            try:
                reader, writer = await conn.open_connection(target_ip, target_port)
            except asyncssh.Error:
                return False

            writer.write(b'\r\n')
            writer.write_eof()

            response = await reader.read()
            return POSITIVE_HIT_STRING in response
    except (asyncssh.Error, OSError):
        return False


async def check_with_credentials_group(ip, target_ip, target_port, credentials_group=DEFAULT_CREDENTIALS):
    futures = [check_with_credentials(ip, target_ip, target_port, c[0], c[1]) for c in credentials_group]
    results = await asyncio.gather(*futures)

    return True in results


async def check_connecting_client(bot, ip):
    result = await check_with_credentials_group(ip, TARGET_IP, TARGET_PORT)
    if result:
        print('found vulnerable SSH daemon at', ip)
        bot.writeln(KLINE_CMD_TEMPLATE.format(ip=ip))

        if dnsbl_active:
            tasks = []
            if dronebl_key: tasks += [submit_dronebl(ip)]
            if dnsbl_im_key: tasks += [submit_dnsbl_im(ip)]
            await asyncio.wait(tasks)


def main():
    logging.basicConfig(level=logging.DEBUG)
    bot = irc.connect(HOST, PORT, use_ssl=USE_SSL)
    bot.register(NICKNAME, "antissh", "antissh proxy checking bot")

    @bot.on('irc-001')
    def handle_connection_start(message):
        bot.writeln("OPER {}\r\n".format(OPER))
        if MODES:
            bot.writeln("MODE {0} {1}\r\n".format(NICKNAME, MODES))

    @bot.on('notice')
    def handle_connection_notice(message, user, target, text):
        if 'connecting' not in text:
            return

        match = IP_REGEX.search(text)
        if match:
            ip = match.group(1)
            
            if ip in ('0', '255.255.255.255', '127.0.0.1', '::1'):
                return

            asyncio.ensure_future(check_connecting_client(bot, ip))

    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    main()
