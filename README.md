iptables-mod-randmap
===================

> **Warning**
>
> This is still an experimental & in-development project.
> It is not fully tested and seems to cause a kernel panic.

An `iptables-extensions(8)` that added a `RANDMAP` target for stateless
addresses / port randomization.

Just provide a prefix and/or a port range, RANDMAP will randomly choose an
address and/or a port for every IP packet, set them to the IP packet, and fix
the checksum, that's all.

In fact, you can also set a /128 as prefix and 80:80 as port range, which let
you set those attributes in the IP packet freely.

RANDMAP is stateless, it is not designed to be a NAT or pass any
conntrack-based firewall.


## Build & Install

```
make install-all
```

The above command will install a kernel module at 
`/lib/modules/$(uname -r)/extra/xt_RANDMAP.ko.zst`
as well as a xtables extensions at
`$(pkg-config xtables --variable xtlibdir)/libxt_RANDMAP.so`


## Example & Intended Usage

For example, you have the following 2 nodes act as server and client.

+ Server
  + Address: fc00:2070::1/128
  + Prefix: fc00:3001::/64

+ Client
  + Address: fc00:2070::1/128

Set the following ip6tables rules on server node:

```
ip6tables -t mangle -A PREROUTING -d fc00:3002::/64 -j RANDMAP --dst-pfx fc00:2070::2/128 --dport 80:80
ip6tables -t mangle -A OUTPUT -s fc00:2070::2 -p tcp --sport 80 -j RANDMAP --src-pfx fc00:3002::/64 --sport 0:65535
```

And set the following ip6tables rules on client node:

```
ip6tables -t mangle -A OUTPUT -d fc00:2070::2 -p tcp --dport 80 -j RANDMAP --dst-pfx fc00:3002::/64 --dport 0:65535
ip6tables -t mangle -A PREROUTING -s fc00:3002::/64 -j RANDMAP --src-pfx fc00:2070::2/128 --sport 80:80
```

Assuming you have an HTTP server on the server node, listening on :80.

On the client node, execute the following curl command:

```
curl http://[fc00:2070::2]
```

The IP packets during this TCP connection would be like:

```
# tcpdump tcp -i qemu_arch2 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on qemu_arch2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
12:31:19.757741 IP6 fc00:2070::1.50982 > fc00:3002::9f19:5a19:ea3f:2f82.41346: Flags [S], seq 3607979275, win 64800, options [mss 1440,sackOK,TS val 1863243187 ecr 0,nop,wscale 7], length 0
12:31:19.757964 IP6 fc00:3002::3468:9d19:37c2:d11f.47263 > fc00:2070::1.50982: Flags [S.], seq 4179963945, ack 3607979276, win 64260, options [mss 1440,sackOK,TS val 2734266744 ecr 1863243187,nop,wscale 7], length 0
12:31:19.758057 IP6 fc00:2070::1.50982 > fc00:3002::998d:f5bb:49b6:d325.60902: Flags [.], ack 4179963946, win 507, options [nop,nop,TS val 1863243188 ecr 2734266744], length 0
12:31:19.758119 IP6 fc00:2070::1.50982 > fc00:3002::5050:8fa5:99d7:74d0.27672: Flags [P.], seq 3607979276:3607979354, ack 4179963946, win 507, options [nop,nop,TS val 1863243188 ecr 2734266744], length 78
12:31:19.758216 IP6 fc00:3002::32fb:55bc:239c:308c.22618 > fc00:2070::1.50982: Flags [.], ack 3607979354, win 502, options [nop,nop,TS val 2734266744 ecr 1863243188], length 0
12:31:19.758654 IP6 fc00:3002::8b5:40bf:a6f6:953a.dsmcc-config > fc00:2070::1.50982: Flags [.], seq 4179963946:4179965374, ack 3607979354, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758665 IP6 fc00:3002::8b5:40bf:a6f6:953a.dsmcc-config > fc00:2070::1.50982: Flags [.], seq 1428:2856, ack 1, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758669 IP6 fc00:3002::8b5:40bf:a6f6:953a.dsmcc-config > fc00:2070::1.50982: Flags [P.], seq 2856:4096, ack 1, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1240
12:31:19.758719 IP6 fc00:2070::1.50982 > fc00:3002::6043:5fe7:1996:290a.56399: Flags [.], ack 4179968042, win 489, options [nop,nop,TS val 1863243188 ecr 2734266745], length 0
12:31:19.758765 IP6 fc00:3002::1221:96fd:c5ce:25a6.22257 > fc00:2070::1.50982: Flags [.], seq 4179968042:4179969470, ack 3607979354, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758772 IP6 fc00:3002::1221:96fd:c5ce:25a6.22257 > fc00:2070::1.50982: Flags [.], seq 1428:2856, ack 1, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758776 IP6 fc00:3002::1221:96fd:c5ce:25a6.22257 > fc00:2070::1.50982: Flags [.], seq 2856:4284, ack 1, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758780 IP6 fc00:3002::1221:96fd:c5ce:25a6.22257 > fc00:2070::1.50982: Flags [.], seq 4284:5712, ack 1, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758784 IP6 fc00:3002::1221:96fd:c5ce:25a6.22257 > fc00:2070::1.50982: Flags [P.], seq 5712:7140, ack 1, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1428
12:31:19.758799 IP6 fc00:3002::2a7a:3d0:da8f:ce8f.16022 > fc00:2070::1.50982: Flags [P.], seq 4179975182:4179976381, ack 3607979354, win 502, options [nop,nop,TS val 2734266745 ecr 1863243188], length 1199
12:31:19.758878 IP6 fc00:2070::1.50982 > fc00:3002::2f4f:9d48:d09d:5861.21844: Flags [.], ack 4179975182, win 474, options [nop,nop,TS val 1863243188 ecr 2734266745], length 0
12:31:19.758914 IP6 fc00:2070::1.50982 > fc00:3002::839f:461e:32c:52f6.65195: Flags [.], ack 4179976381, win 466, options [nop,nop,TS val 1863243188 ecr 2734266745], length 0
12:31:19.900520 IP6 fc00:2070::1.50982 > fc00:3002::3bdf:3c09:7638:9b43.47453: Flags [F.], seq 3607979354, ack 4179976381, win 501, options [nop,nop,TS val 1863243330 ecr 2734266745], length 0
12:31:19.900794 IP6 fc00:3002::c7b2:7ea6:4fb0:b528.dnx > fc00:2070::1.50982: Flags [F.], seq 4179976381, ack 3607979355, win 502, options [nop,nop,TS val 2734266887 ecr 1863243330], length 0
12:31:19.900891 IP6 fc00:2070::1.50982 > fc00:3002::3954:e728:1161:7d92.43101: Flags [.], ack 4179976382, win 501, options [nop,nop,TS val 1863243330 ecr 2734266887], length 0
```


## What is its use?

Guess it.

