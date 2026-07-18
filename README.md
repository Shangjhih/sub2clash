该项目是[sub2clash](https://github.com/Shangjhih/sub2clash)的GUI版本，代码实现略有差异，GUI版本源代码参见此项目。

# 脚本类型

1.  `clash_convert_CLI.py`为最初版本，不兼容Hysteria2、TUIC、AnyTLS协议的节点
2.  `clash_convert_CLI_extended.py` 为第一版修改版，兼容以上所有协议
3.  `clash_convert_CLI_extended_fix.py`为修改后的第二版，兼容性须自测

---

**`clash_rules(DNS).yaml` 是yaml配置模板，你可以自行修改模板的配置内容，比如全局配置和TUN设置以及规则，默认配置足以应对各种网络场景，不知道怎么修改配置的可以直接使用。**

**`config.txt`用于存放从V2rayN等客户端复制出来的配置文件**

---

# 支持的代理协议

## 功能特性

✅ 支持多协议解析

✅ 支持多种传输层

✅ 自动识别 TLS / Reality

✅ 自动处理节点重名

✅ 保留原 YAML 配置结构

✅ 保留 Rule Provider

✅ 保留 Proxy Group

✅ 保留 DNS配置

✅ 保留 TUN 配置

✅ 生成标准 Mihomo Proxy 配置

## 支持的通信协议组合

| vless + tcp + tls       | vless + tcp + reality  | vless + ws + tls     |
| ----------------------- | ---------------------- | -------------------- |
| vless + ws + reality    | vless + h2 + tls       | vless + h2 + reality |
| vless + grpc + tls      | vless + grpc + reality | vless + xhttp + tls  |
| vless + xhttp + reality | vmess + tcp + tls      | vmess + ws + tls     |
| anytls + tls            | vmess + xhttp + tls    | trojan + xhttp       |
| trojan + ws             | hysteria2 + tls        | tuic + tls           |

---



# 使用方法

1. 本地安装python，使用以下命令安装下所需依赖：

```
pip install -r requirements.txt
```

2. 将V2rayN或其他平台导出的配置文件粘贴到`config.txt`中
3. 双击执行选定的python，生成的yaml配置文件将会以`clash_year_month_day.yaml`的形式输出至当前文件夹下。