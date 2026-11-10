# XHTTP + HTTP/3

V2bX 使用 Xray 内核承接 VLESS / VMess 的 XHTTP，支持 H1/H2 与基于 QUIC/UDP 的 H3。发布构建和 Docker 构建包含 Xray；单独构建时必须加 `xray` 标签。原有 sing 节点继续使用原内核，不会自动切换。

## 服务端配置

可参考 `example/xhttp.json`。在 `Cores` 中添加 `Type: xray`，对应节点选择 `Core: xray`，节点顶层配置：

```json
{
  "Core": "xray",
  "ApiHost": "https://panel.example.com",
  "ApiKey": "replace-with-panel-key",
  "NodeID": 1,
  "NodeType": "vless",
  "ListenIP": "::",
  "ALPN": ["h3"],
  "CertConfig": {
    "CertMode": "file",
    "CertDomain": "proxy.example.com",
    "CertFile": "/etc/V2bX/fullchain.cer",
    "KeyFile": "/etc/V2bX/cert.key"
  }
}
```

这里 `file` 表示使用自己提供的证书文件；建议使用受信任证书。`self` 会在文件缺失时自动生成自签证书。也可以沿用现有的 http/dns 自动申请证书流程。`ALPN` 同时支持节点顶层写法和 `XrayOptions.ALPN`，显式嵌套配置优先。

面板的 VLESS 节点必须开启普通 TLS、清空 flow，并通过节点接口返回：

```json
{
  "tls": 1,
  "network": "xhttp",
  "network_settings": {
    "path": "/xhttp",
    "mode": "auto"
  }
}
```

保留现有的 `server_port`、用户列表等面板字段。`networkSettings` 和 `splithttp` 别名也兼容。服务端 `auto` 接受 packet-up、stream-up、stream-one；指定具体模式时客户端必须与之兼容。缺省 `network_settings` 时使用内核默认设置；自定义 path 必须与客户端一致。XHTTP 的其他服务端参数按锁定的 Xray 版本解析。

`ALPN: ["h3"]` 让这个入站监听 UDP；需要开放面板节点端口对应的 UDP 防火墙/安全组。它不会同时监听 H2/TCP，也不在 UDP 被阻断时自动降级。H3 不能与 h2 混写，不能搭配 REALITY、Vision flow 或 TCP PROXY protocol。需要 H2 时改为 `ALPN: ["h2"]` 或省略 ALPN，并开放 TCP 端口。

客户端的基础分享链接形如（替换用户 UUID、域名和端口）：

```text
vless://USER_UUID@proxy.example.com:443?encryption=none&security=tls&sni=proxy.example.com&alpn=h3&type=xhttp&mode=packet-up&path=%2Fxhttp#XHTTP-H3
```

面板需要原样输出这些订阅参数。V2bX 是面板节点后端，不生成客户端订阅。仅在服务端配置证书不会自动开启面板 TLS 或改变订阅。客户端需支持 XHTTP/H3；复杂参数使用完整 Xray JSON 配置最容易检查。

## v2board 最小适配

已有面板可沿用 VLESS 的 SplitHTTP 选项（服务端兼容 `splithttp` 别名），不增加表字段或接口。安全性选 TLS，flow 留空；协议配置填：

```json
{
  "path": "/xhttp",
  "mode": "packet-up",
  "alpn": ["h3"]
}
```

其中 `alpn` 是面板生成客户端链接所用的附加字段，Xray 的 XHTTP 参数解析会忽略它；服务端仍需在 V2bX 节点配置中设置 `ALPN: ["h3"]`。面板订阅辅助函数需将 `splithttp`/`xhttp` 规范化为 `type=xhttp`，保留 path、host、mode、alpn，并将 `extra` 对象编码为 JSON 链接参数（可包含 downloadSettings）。

本地 v2board 的最小补丁仅修改 `app/Utils/Helper.php`，覆盖 V2rayN 等使用 VLESS URI 的订阅；不扩展 Clash/Mihomo 或 sing-box 的专用订阅转换器。复制该文件到面板服务器后执行 `php -l app/Utils/Helper.php`、`php artisan optimize:clear`；如启用了不检查文件时间的 OPcache，还需重载 PHP-FPM。重新获取原始 VLESS 链接并核对 `type=xhttp`、`alpn=h3`、`mode=packet-up`；复杂分离参数还应核对解码后的 extra。

## 上下行分离

packet-up 用 POST 上传、GET 响应下载；stream-up 使用流式 POST 上传和独立 GET 下载；stream-one 在一个双向请求中传输，不用于独立入口分离。不同 HTTP 请求可以复用底层连接，默认配置不意味着独立线路。

要明确选择不同的下载入口，在客户端的 `streamSettings.xhttpSettings.extra` 中加入：

```json
{
  "downloadSettings": {
    "address": "download.example.com",
    "port": 443,
    "network": "xhttp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "proxy.example.com",
      "alpn": ["h3"]
    },
    "xhttpSettings": {
      "path": "/xhttp"
    }
  }
}
```

上传入口仍取客户端原来的 address/port/streamSettings。下载入口的证书需匹配其 serverName。下载配置独立，不继承上传的 TLS、Host 等参数，应按入口情况完整填写。

上下行可以使用不同域名、IP、端口、IPv4/IPv6、H2/TCP 或 H3/UDP，并经过不同 CDN/转发服务器，但最后必须抵达**同一个 XHTTP 入站实例、同一个 path**。不同入口要做好转发：两个独立 V2bX 节点或两个独立入站即使 UUID/path 相同，也不会共享会话。多后端负载均衡也必须确保一对上下行抵达同一实例。

例如两个 UDP 入口都转发到同一个 H3 入站；或让支持 H2/H3 的 HTTP 前端把上下行都转到同一个 H2 XHTTP 入站。混合 H2/H3 不通过给 H3 专用监听增加 h2 ALPN 实现。无需新增服务端“分离开关”，服务端按会话 ID 配对，用户认证与计费仍在同一个 VLESS 会话处理。

## 已知上游限制

v26.11.9 的全链路 race 检查仍能复现官方 Xray TLS 证书热重载的并发读写告警。正常模式的连接测试通过，但不能据此声称依赖已通过全链路 race 检查。V2bX 撤销连接时发现的并发问题已在本项目修复。CI 对配置和 dispatcher 执行 race 检查，对真实 H3 连接单独执行功能测试；升级兼容工作流另行记录全链路 race 探测结果，上游问题仍需后续验证。

## 构建与验证

```bash
GOWORK=off GOEXPERIMENT=jsonv2 go build -tags 'sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor' -o V2bX .
GOWORK=off GOEXPERIMENT=jsonv2 go test -tags xray ./core/xray -run TestXHTTP -timeout 90s
GOWORK=off GOEXPERIMENT=jsonv2 go test ./conf -run TestXrayALPN
```

测试在本地创建证书和实际 H2/H3 入站，通过 Xray 客户端验证三种模式的数据往返、两个独立 UDP 入口的会话配对、用户流量统计和删除用户后的拒绝连接。

Xray 依赖锁定官方 v26.11.9 发布提交（Go 模块 `v1.260327.1-0.20261109052709-676eaf66f8f0`），构建使用 Go 1.27.3。后续升级与兼容边界见 [内核升级说明](xray-upgrades.md)。原分支特有的 `DisableIVCheck: true` 不再受支持并会报错；旧 KCP header 伪装也不由这个版本提供。自定义 Xray 入站/出站必须符合该版本格式，例如自签证书客户端使用证书固定（pinnedPeerCertSha256），不要照搬旧脚本的 allowInsecure。sing 节点的配置格式不受此项迁移影响。
