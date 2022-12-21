tomato
======

本项目包含三个独立的可执行文件：

1. `vpn` 是点对点加密 VPN 实现，用于建立隐秘的网络层链路。（Linux）
2. `ping` 是支持 IPv4/IPv6 的 Ping 实现，用于 `vpn` 的心跳检测。（Unix）
3. `proxy` 是支持规则的 HTTP 代理实现，配合 `vpn` 可取代常见的加密代理工具。

install
-------

1. 安装 `go` 和依赖库 `google.org/x/sys` （`go get`）。
2. 在根目录执行 `make` ，三个可执行文件将生成到 `bin` 目录。
3. （Optional）`scripts/dlmerge.py` 将 [domain-list](https://github.com/v2fly/domain-list-community) 转化为 `proxy` 的规则文件。

vpn
===

`vpn` 是基于 Linux `tun/tap` 机制的类似于 `wireguard` 的点对点加密 VPN 实现。
VPN 两端节点是对等的，在各自的角度分别称为 local 和 peer，各自使用独立的密码加密网络层的报文。

PS. local 和 peer 是对等的，不能基于身份从一个密码中生成不同的密钥，因此 local 和 peer 应各自使用独立的密码。

basic
-----

以主机 A（192.168.8.130）连接主机 B（192.168.8.131）为例：

```sh
# 新建名为 tun0 的 tun 类型设备
ip tuntap add dev tun0 mode tun

# 开启 tun0
ip l set tun0 up

# （优化）配置 tun0 MTU
ip l set tun0 mtu 1400

# 配置 tun0 IPv4 地址
ip a add 10.0.1.1/30 dev tun0

# （优化）关闭 tun0 IPv6 协议栈
echo 1 > /proc/sys/net/ipv6/conf/tunl/disable_ipv6

# 运行 vpn
# la: local address
# lp: local password
# pa: peer address
# pp: peer password
# v:  verbose
vpn -la :5000 -lp pwd1 -pa 192.168.8.131:5000 -pp pwd2 -v
```

主机 B 也使用相同的方法连接主机 A，这样就建立了点对点加密网络 `10.0.1.1/30 <=> 10.0.1.2/30`。

PS. 通常将点对点网络的前缀长度配置为 /30，包含 4 个地址 0、1、2、3，分别表示网络本身、两端节点和广播地址。

PS. 报头长度：'((IPv4 . 20) (IPv6 . 40) (UDP . 8) (`vpn` . 44))，在使用时最好酌情配置 MTU，例如 `1500 - 40 - 8 - 44 = 1408`。

PS. IPv6 在点对点链路上相对 IPv4 没有任何优势：路由优化没有效果、报头更长、频繁发送无用报文等等，在使用时最好关闭 IPv6 协议栈。

gateway
-------

如果想要将主机 A 作为主机 B 的网关，两个主机都需要额外的配置。

主机 A 的额外配置：

```sh
# 开启 IPv4 路由转发
echo 1 > /proc/sys/net/ipv4/ip_forward

# 配置 NAT
iptables -t nat -A POSTROUTING -s 10.0.1.0/30 -o ens33 -j MASQUERADE
```

PS. `iptables` 的 `MASQUERADE` 即根据出口接口的地址自动配置 NAT。

主机 B 的额外配置：

```sh
# 添加主机 A 路由规则
ip r add 192.168.8.130 via x.x.x.x dev ens33

# 配置网关
ip r add default via 10.0.1.1/30 dev tun0

# 配置 DNS
vim /etc/resolv.conf
```

PS. 为确保发送给主机 A（192.168.8.130）的 UDP 报文可以正常转发，应在改变网关前添加正确的路由规则。

PS. 主机 B 应配置正确的 DNS 服务器地址，通常与主机 A 的 DNS 服务器地址相同。

dynamic update
--------------

VPN 两端节点不必都预先知道对端地址，其中一端可以等收到对端报文时动态更新地址，称为动态更新模式。

动态更新模式适用于无法固定 peer 的地址的场景，例如 NAT 地址转换或切换网络、设备。

继续前面的例子，如果主机 A 无法固定主机 B 的地址，`vpn` 的参数应做出如下改变：

```sh
vpn -la :5000 -lp pwd1 -d -pp pwd2 -v
```

注意到 `-pa 192.168.8.131:5000` 变为 `-d`。

更进一步，在一个具有公网地址的节点上通过动态更新模式建立两个连接并开启路由转发可以连接两个内网节点。

PS. 在动态更新模式下，如果未收到第一个报文或长时间（默认 60s）未收到报文，会造成连接丢失。

protocol
--------

TODO

ping
====

`ping` 和众所周知的同名命令功能一致：周期性（默认 30s）Ping 目标主机，并使用 `go` 的 `log` 输出结果。

在这里提供 `ping` 的目的是为使用动态更新模式的 `vpn` 创建的连接提供心跳检测。

继续前面的例子，如果主机 B 想要保证对端不会丢失连接：

```sh
ping -a 10.0.1.1
```

proxy
=====

`proxy` 是支持规则的 HTTP 代理实现，与 `vpn` 配合可以取代 `v2ray`、`trojan` 等加密代理工具。

与通过 `vpn` 将对端当作网关相比，我更推荐在连接两端部署 `proxy`，配置规则按需访问对端：

```sh
# 配置环境变量（Unix）
export ALL_PROXY=http://localhost:1080

# 运行 proxy
# a：local address
# f：forward address
# r：rule file
proxy -a :1080 -f 10.0.1.1:1080 -r rule.txt -v
```

这样，支持代理协议的应用，例如浏览器和包管理器等，将使用本地 `proxy`，后者根据规则决定如何处理请求，例如将请求转发给对端 `proxy`。

rule
----

`proxy` 对于一个请求有三个处理方式：

1. `block`：丢弃请求。
2. `direct`：在本地处理请求。
3. `forward`：将请求转发给对端，如果未设置对端则按照 `direct` 处理。

规则文件的格式如下：

```txt
# comment

block	ads.baidu.com
direct	baidu.com
forward	github.com
```

`proxy` 将忽略所有注释和空行，将所有规则按照 "direction	domain"（注意中间为 TAB） 解析。
如果一个域名出现多次，则以第一次为准，因此用户可以编辑文件头来覆盖后面的规则。

规则匹配将逐步匹配根域名直至匹配成功，例如匹配域名 www.baidu.com 时将依次匹配 www.baidu.com、baidu.com 和 com。
命令行参数 `-d DIRECTION` 决定默认的处理方式，默认为 `direct`。

PS. `proxy` 即使不用来做分流，也可以用来做广告过滤器。

PS. `script/dlmerge.py` 将 [domain-list](https://github.com/v2fly/domain-list-community) 转化为 `proxy` 的规则文件可能满足你的需求。

TODO
====

1. `udp2tcp`：基于 Linux 的 `netfilter_queue` 实现 UDP 连接转 TCP 连接，解决 UDP 和 TCP 的 QoS 不对等的问题。
