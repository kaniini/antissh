# antissh

An IRC bot which monitors for compromised embedded devices being used as proxies.


## background

In 2018, there was a resurgence of IRC spam attacks that were undetected by traditional
proxy scanning methods.  This is because the attackers were using vulnerable SSH daemons
running on routers, IPMI devices and other embedded devices to proxy the connections, using
the `direct-tcpip` subsystem.

`antissh` is a bot which scans incoming IRC connections for this vulnerability, and bans
hosts which have it from your network, similar to how [HOPM][hopm] does this for normal
proxies.

   [hopm]: https://github.com/ircd-hybrid/hopm


## usage

```
$ pip3 install -r requirements.txt
$ cp antissh.conf.example antissh.conf
$ vi antissh.conf
$ python3.6 antissh.py antissh.conf
```

You should probably use this under a supervisor such as OpenRC's supervise-daemon(8), systemd,
s6, runit, etc.


## known issues

`asyncssh` is kind of slow, would be nice to write an implementation of this bot in C, Go,
Elixir or something faster.  But, I will leave that to somebody else.
