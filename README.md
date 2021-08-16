Drop ServerHello with netfilter\_queue. For testing [bug 1718719](https://bugzilla.mozilla.org/show_bug.cgi?id=1718719) of Firefox.

Setup (works with ip6tables too):

```
iptables -A INPUT -p tcp -s IP_ADDR --sport 443 -j NFQUEUE --queue-num 9 --queue-bypass
```
