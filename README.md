# V2bX

[![](https://img.shields.io/badge/TgChat-UnOfficialV2Board%E4%BA%A4%E6%B5%81%E7%BE%A4-green)](https://t.me/unofficialV2board)
[![](https://img.shields.io/badge/TgChat-YuzukiProjects%E4%BA%A4%E6%B5%81%E7%BE%A4-blue)](https://t.me/YuzukiProjects)

A V2board node server based on multi core, modified from XrayR.  
一个基于多种内核的V2board节点服务端，修改自XrayR，支持V2ay,Trojan,Shadowsocks协议。

**注意： 本项目需要搭配[修改版V2board](https://github.com/wyx2685/v2board)**

## 特点

* 永久开源且免费。
* 支持Vmess/Vless, Trojan， Shadowsocks, Hysteria1/2多种协议。
* 支持Vless和XTLS等新特性。
* 支持单实例对接多节点，无需重复启动。
* 支持限制在线IP。
* 支持限制Tcp连接数。
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 支持多种内核，易扩展。
* 支持条件编译，可仅编译需要的内核。

## 功能介绍

| 功能        | v2ray | trojan | shadowsocks | hysteria1/2 |
|-----------|-------|--------|-------------|----------|
| 自动申请tls证书 | √     | √      | √           | √        |
| 自动续签tls证书 | √     | √      | √           | √        |
| 在线人数统计    | √     | √      | √           | √        |
| 审计规则      | √     | √      | √           | √         |
| 自定义DNS    | √     | √      | √           | √        |
| 在线IP数限制   | √     | √      | √           | √        |
| 连接数限制     | √     | √      | √           | √         |
| 跨节点IP数限制  |√      |√       |√            |√          |
| 按照用户限速    | √     | √      | √           | √         |
| 动态限速(未测试) | √     | √      | √           | √         |

## TODO

- [ ] 重新实现动态限速
- [ ] 完善使用文档

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/xshhhlol/V2bX-script/master/install.sh && bash install.sh
```

### 手动安装

[手动安装教程](https://v2bx.v-50.me/v2bx/v2bx-xia-zai-he-an-zhuang/install/manual)

## 构建
``` bash
# 通过-tags选项指定要编译的内核， 可选 xray， sing, hysteria2
GOEXPERIMENT=jsonv2 go build -v -o build_assets/V2bX -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -trimpath -ldflags "-X 'github.com/InazumaV/V2bX/cmd.version=$version' -s -w -buildid="
```

## 配置文件及详细使用教程

[详细使用教程](https://v2bx.v-50.me/)

### sing 内核的 TLS 回落网站

Trojan / AnyTLS 的 TLS 节点，以及没有 HTTP header 等额外传输封装的 TCP VMess 节点，可在节点配置中启用内置静态网站：

```json
"FallBackSite": {
  "Enable": true,
  "Root": "/etc/V2bX/www"
}
```

将自己的 `index.html`、样式和其他页面放到该目录。目录为空或不存在时使用内置 Notes 示例网站，包含首页、关于页和样式文件；建议部署时替换为自己的内容。已指定 `FallBackConfigs` 时优先使用外部回落。

网站支持 HTTP/1.1 和 HTTP/2、GET/HEAD、范围请求及条件缓存。内置资源使用内容 ETag，自定义文件使用 Last-Modified；缺失页面返回 404，不支持的方法返回 405，隐藏文件和没有首页的目录不提供列表。不会为了改变响应大小而随机追加内容。回落仅处理未认证连接，不改变正常代理业务的内容。

VMess 可另外配置兼容现有客户端的下行整形和握手期限：

```json
"VMessConfig": {
  "RequireEncryption": false,
  "HandshakeTimeout": 30,
  "TrafficShaping": { "Enable": true }
}
```

`RequireEncryption` 只在没有外层 TLS 时生效；开启后会拒绝 none/CFB 客户端，因此保留此类客户端时使用 false。WS、gRPC、HTTPUpgrade 的请求由传输层处理，不会自动回落到上述静态网站。整形不改变应用数据，不要求新增客户端功能，也不保证流量与普通 HTTPS 无法区分。

V2bX v1.4.1 起包含分段头部、完整时间戳窗口重放防护和旧版 alterId 兼容路径的修复，发布依赖已锁定到对应的 sing-vmess 提交。已有节点更新服务端二进制并重启后生效，客户端无需升级。本地开发可通过 go.work 使用并列的 sing-vmess，或使用 V2bX-script 仓库的 `build-vmess-local.sh` 构建本地修改。

## 免责声明

* 此项目用于本人自用，因此本人不能保证向后兼容性。
* 由于本人能力有限，不能保证所有功能的可用性，如果出现问题请在Issues反馈。
* 本人不对任何人使用本项目造成的任何后果承担责任。
* 本人比较多变，因此本项目可能会随想法或思路的变动随性更改项目结构或大规模重构代码，若不能接受请勿使用。

## 赞助

[赞助链接](https://v-50.me/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)
* [XrayR](https://github.com/XrayR/XrayR)
* [sing-box](https://github.com/SagerNet/sing-box)

## Stars 增长记录

[![Stargazers over time](https://starchart.cc/xshhhlol/V2bX.svg)](https://starchart.cc/xshhhlol/V2bX)
