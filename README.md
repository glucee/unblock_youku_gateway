# Unblock-Youku Gateway
Implementation of Unblock-Youku function in Gateway Server 在网关服务器中实现unblockyouku功能。

Unblock Gateway 是一个帮助配置 Shadowsocks 回国代理分流的命令行小工具，实现通过网关服务器自动分流，将国内一些网站的访问通过 Shadowsocks 代理回国，用以解除这些网站的海外访问限制，其它流量则会正常直连不走回国代理。本Repo可以搭建在树莓派、任何一台局域网Linux机器，其他机器只需要设置该网关，或者通过路由器设置该网关。

分流规则提取自 [Unblock Youku](https://github.com/uku/Unblock-Youku)，Unblock Youku 的规则中一般只包含站点用于检测的地址 ，不包含实际音视频流的地址，因此大部分情况下音视频流可以直连不用走代理，这样可以避免音视频变慢，也可以有效节约代理服务器的流量。

### 来源与修改

本Repo大多数功能来自于[unblockchn](https://github.com/gxfxyz/unblockchn/)，感谢原作者。本Repo主要为了解决没有华硕梅林路由器，但仍然想让路由器下的所有设备都可以使用unblock youku的情况。

网关其实含义非常丰富，可以是树莓派，可以是家庭服务器，也可以是一台独立的PC，甚至还可以是PC上虚拟机。由于网关即为路由中的下一跳，所以局域网内所有的数据都会首先被发送到这台网关上，由它再来判断是直接发给目标地址，还是走ss。[见参考](https://medium.com/@oliviaqrs/%E5%88%A9%E7%94%A8shadowsocks%E6%89%93%E9%80%A0%E5%B1%80%E5%9F%9F%E7%BD%91%E7%BF%BB%E5%A2%99%E9%80%8F%E6%98%8E%E7%BD%91%E5%85%B3-fb82ccb2f729)

![网关示意图](https://cdn-images-1.medium.com/max/1000/1*0ya9yYQFUNAbwp_eKY58Cw.jpeg)

### 准备

当然前提是你需要有一台位于国内的 Shadowsocks 服务器，在国内的路由器上[部署 Shadowsocks 服务器端](https://github.com/gxfxyz/unblockgw/wiki/在华硕梅林固件（Asuswrt-Merlin）网关上部署-Shadowsocks-服务器端（ss-server）)也是可行的。

### Unblock Gateway 的功能有：

* 网关
    + [原理](#%E5%8E%9F%E7%90%86)
    + [安装](#%E5%AE%89%E8%A3%85)
    + [使用](#%E4%BD%BF%E7%94%A8)
        - [一键配置网关](#一键配置网关)
        - [查看代理状态](#%E6%9F%A5%E7%9C%8B%E4%BB%A3%E7%90%86%E7%8A%B6%E6%80%81)
        - [关闭代理](#%E5%85%B3%E9%97%AD%E4%BB%A3%E7%90%86)
        - [开启代理](#%E5%BC%80%E5%90%AF%E4%BB%A3%E7%90%86)
        - [检查 <URL/IP/域名> 是否走代理](#%E6%A3%80%E6%9F%A5-urlip%E5%9F%9F%E5%90%8D-%E6%98%AF%E5%90%A6%E8%B5%B0%E4%BB%A3%E7%90%86)
        - [更新规则](#%E6%9B%B4%E6%96%B0%E8%A7%84%E5%88%99)
        - [仅生成 ipset 规则配置文件](#仅生成ipset规则配置文件)
        - [修改规则模板](#%E4%BF%AE%E6%94%B9%E8%A7%84%E5%88%99%E6%A8%A1%E6%9D%BF)
    + [配置](#配置网关上网)

---

### 原理

1. 从 Unblock Youku 的 [urls.js](https://github.com/uku/Unblock-Youku/blob/master/shared/urls.js) 中提取分流规则。

2. 根据分流规则生成 dnsmasq 和 ipset 规则，将需要回国代理的 IP 地址加入 chn ipset。

3. 添加 iptables 规则，将属于 chn ipset 的请求转发到 Shadowsocks 透明代理工具 ss-redir 的端口，通过 Shadowsocks 代理回国。

Unblock Gateway 自动化以上过程，提供了一键配置网关的命令和一些管理命令。

### 安装

1. 安装依赖程序：

```console
# Shadowsocks 透明代理工具 ss-redir
$ sudo apt-get install shadowsocks-libev
```

2. 安装 Unblock Gateway：

```console
# 安装 Unblock Gateway
$ git clone https://github.com/glucee/unblockyouku_gateway.git

# 进入 Unblock Gateway 目录
$ cd unblock_gateway

# 安装 Unblock Gateway 依赖
$ pip3 install -r requirements.txt
```

### 使用

```console
$ sudo python3 unblockgw.py --help
usage: sudo python3 unblockgw.py router [-h] {status,on,off,check,renew,setup,create}

Unblock Gateway 网关命令：
  status                  查看代理状态
  on                      开启代理
  off                     关闭代理
  check <URL/IP/域名>     检查 <URL/IP/域名> 是否走代理
  renew                   更新规则
  setup [--no-ss]         一键配置网关 [--no-ss: 跳过配置 ss-redir]
  create                  仅生成 ipset 规则配置文件

positional arguments:
  {status,on,off,check,renew,setup,create}

optional arguments:
  -h, --help            show this help message and exit
```

#### 一键配置网关

```console
$ sudo python3 unblockgw.py setup
```

如果想要跳过配置 ss-redir，那么就加上 --no-ss 参数：

```console
$ sudo python3 unblockgw.py setup --no-ss
```

至此，回国代理和自动分流就配置并开启好了。

可以访问下列地址以验证回国代理是否成功，如果显示 `true`，就说明回国代理已生效： 

http://uku.im/check

#### 查看代理状态

```console
$ sudo python3 unblockgw.py status
已开启
```

#### 关闭代理

```console
$ sudo python3 unblockgw.py off
关闭成功
```
#### 开启代理

```console
$ sudo python3 unblockgw.py on
开启成功
```

#### 检查 <URL/IP/域名> 是否走代理

```console
$ sudo python3 unblockgw.py check http://ipservice.163.com/isFromMainland
59.111.19.7 走代理

$ sudo python3 unblockgw.py check https://google.com
216.58.193.78 不走代理

$ sudo python3 unblockgw.py check www.bilibili.com
148.153.45.166 走代理

$ sudo python3 unblockgw.py check 192.168.2.1
192.168.2.1 不走代理
```

#### 更新规则

```console
$ sudo python3 unblockgw.py router renew
```

Unblock Gateway 在网关上默认定时每日 03:00 自动更新分流规则，及时跟进 Unblock Youku 规则的变化。

#### 仅生成ipset规则配置文件

```console
$ sudo python3 unblockgw.py router create
生成配置文件成功
```

此命令让 Unblock Gateway 跳过配置网关，仅提取 Unblock Youku 的规则，在 `configs` 目录下生成相应的 ipset 规则配置文件。

#### 修改规则模板

除了 Unblock Gateway 自动生成的规则以外，如果你需要自定义一些 ipset 规则，可以通过修改 `configs` 目录下的规则模板文件 `ipset.rules.tpl` 来实现。

保留模板文件中的 `{rules}` 一行，其在生成规则时会被 Unblock Gateway 规则替换，然后在模板文件中添加你需要的规则，例如：

ipset.rules.tpl
```
{rules}
create blacklist hash:ip family inet hashsize 1024 maxelem 65536
add blacklist 103.31.6.5
add blacklist 208.73.51.100
```

运行更新规则命令来使自定义的规则生效：

```console
$ python3 unblockgw.py router renew
```

### 配置网关上网

如果你的网关服务器地址是192.168.1.XX，可以在路由器界面上配置网关为该地址，那么，所有连上该服务器的设备都会经过该网关服务器分流，也就自动使用了Unblock-Youku，注意DNS地址仍然采用之前的地址，或者使用8.8.8.8

### 感谢

感谢Unblockchn和Unblock-Youku作者
