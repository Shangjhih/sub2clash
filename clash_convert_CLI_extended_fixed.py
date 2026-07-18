#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI 版：读取脚本目录中的 TXT 节点与 YAML 模板，生成当日完整 Clash 配置。"""

from __future__ import annotations

import base64
import json
import re
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import yaml




class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def b64_decode_padded(value: str) -> str:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value).decode("utf-8", errors="replace")


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def split_alpn(value: str | None) -> list[str] | None:
    if not value:
        return None
    items = [item.strip() for item in re.split(r"[,|]", value) if item.strip()]
    return items or None


def normalize_network(value: str | None) -> str:
    network = (value or "tcp").strip().lower()
    aliases = {
        "raw": "tcp",
        "http": "h2",
        "http/2": "h2",
        "websocket": "ws",
        "splithttp": "xhttp",
    }
    return aliases.get(network, network)


def parse_query(query: str) -> dict[str, str]:
    return {key: value for key, value in parse_qsl(query, keep_blank_values=True)}


def parse_standard_url(line: str) -> dict[str, Any]:
    parsed = urlsplit(line)
    if not parsed.scheme:
        raise ValueError("missing URL scheme")
    if not parsed.hostname:
        raise ValueError("missing server host")
    if parsed.port is None:
        raise ValueError("missing server port")

    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    return {
        "scheme": parsed.scheme.lower(),
        "username": username,
        "password": password,
        "server": parsed.hostname,
        "port": parsed.port,
        "params": parse_query(parsed.query),
        "name": unquote(parsed.fragment) if parsed.fragment else "",
    }


def parse_vless(line: str) -> dict[str, Any]:
    data = parse_standard_url(line)
    if not data["username"]:
        raise ValueError("missing VLESS UUID")
    data["type"] = "vless"
    data["uuid"] = data["username"]
    data["name"] = data["name"] or f"VLESS-{data['server']}:{data['port']}"
    return data


def parse_trojan(line: str) -> dict[str, Any]:
    data = parse_standard_url(line)
    if not data["username"]:
        raise ValueError("missing Trojan password")
    data["type"] = "trojan"
    data["password"] = data["username"]
    data["name"] = data["name"] or f"Trojan-{data['server']}:{data['port']}"
    return data


def parse_ss(line: str) -> dict[str, Any]:
    parsed = urlsplit(line)
    if parsed.scheme.lower() != "ss":
        raise ValueError("not a Shadowsocks link")

    params = parse_query(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else ""

    if parsed.hostname and parsed.port is not None:
        if parsed.password is not None:
            cipher = unquote(parsed.username or "")
            password = unquote(parsed.password or "")
        else:
            userinfo = unquote(parsed.username or "")
            decoded = b64_decode_padded(userinfo)
            cipher, password = decoded.split(":", 1)
        server = parsed.hostname
        port = parsed.port
    else:
        raw = line[5:].split("#", 1)[0].split("?", 1)[0]
        decoded = b64_decode_padded(raw)
        userinfo, server_part = decoded.rsplit("@", 1)
        cipher, password = userinfo.split(":", 1)
        server, port_text = server_part.rsplit(":", 1)
        port = int(port_text)

    return {
        "type": "ss",
        "name": name or f"SS-{server}:{port}",
        "server": server,
        "port": port,
        "cipher": cipher,
        "password": password,
        "params": params,
    }


def parse_vmess(line: str) -> dict[str, Any]:
    payload = line[8:]
    try:
        decoded = b64_decode_padded(payload)
        if decoded.lstrip().startswith("{"):
            raw = json.loads(decoded)
            return {
                "type": "vmess",
                "name": raw.get("ps") or f"VMess-{raw.get('add')}:{raw.get('port')}",
                "server": raw.get("add", ""),
                "port": int(raw.get("port", 0)),
                "uuid": raw.get("id", ""),
                "alter_id": int(raw.get("aid") or 0),
                "cipher": raw.get("scy") or "auto",
                "network": normalize_network(raw.get("net")),
                "params": {
                    "type": raw.get("net") or "tcp",
                    "headerType": raw.get("type") or "",
                    "host": raw.get("host") or "",
                    "path": raw.get("path") or "",
                    "security": raw.get("tls") or "none",
                    "sni": raw.get("sni") or "",
                    "alpn": raw.get("alpn") or "",
                    "fp": raw.get("fp") or "",
                },
            }
    except Exception:
        pass

    data = parse_standard_url(line)
    params = data["params"]
    data.update(
        {
            "type": "vmess",
            "uuid": data["username"],
            "alter_id": int(params.get("alterId") or params.get("aid") or 0),
            "cipher": params.get("cipher") or params.get("scy") or "auto",
            "network": normalize_network(params.get("type")),
        }
    )
    data["name"] = data["name"] or f"VMess-{data['server']}:{data['port']}"
    return data



def parse_hysteria2(line: str) -> dict[str, Any]:
    data = parse_standard_url(line)
    if not data["username"]:
        raise ValueError("missing Hysteria2 password")
    data["type"] = "hysteria2"
    data["password"] = data["username"]
    data["name"] = data["name"] or f"Hysteria2-{data['server']}:{data['port']}"
    return data


def parse_tuic(line: str) -> dict[str, Any]:
    data = parse_standard_url(line)

    # TUIC v5 分享链接常见两种 userinfo：uuid:password@host，或把冒号
    # 百分号编码成 uuid%3Apassword@host。parse_standard_url 已完成 URL 解码，
    # 因此同时兼容这两种写法。
    if data["password"]:
        uuid, password = data["username"], data["password"]
    elif ":" in data["username"]:
        uuid, password = data["username"].split(":", 1)
    else:
        raise ValueError("missing TUIC v5 UUID or password")

    if not uuid or not password:
        raise ValueError("missing TUIC v5 UUID or password")
    data["type"] = "tuic"
    data["uuid"] = uuid
    data["password"] = password
    data["name"] = data["name"] or f"TUIC-{data['server']}:{data['port']}"
    return data


def parse_anytls(line: str) -> dict[str, Any]:
    data = parse_standard_url(line)
    if not data["username"]:
        raise ValueError("missing AnyTLS password")
    data["type"] = "anytls"
    data["password"] = data["username"]
    data["name"] = data["name"] or f"AnyTLS-{data['server']}:{data['port']}"
    return data

def parse_node(line: str) -> dict[str, Any]:
    scheme = line.split(":", 1)[0].lower()
    if scheme == "vless":
        return parse_vless(line)
    if scheme == "vmess":
        return parse_vmess(line)
    if scheme == "ss":
        return parse_ss(line)
    if scheme == "trojan":
        return parse_trojan(line)
    if scheme in {"hysteria2", "hy2"}:
        return parse_hysteria2(line)
    if scheme == "tuic":
        return parse_tuic(line)
    if scheme == "anytls":
        return parse_anytls(line)
    raise ValueError(f"unsupported scheme: {scheme or '<empty>'}")


def add_tls_fields(proxy: dict[str, Any], params: dict[str, str], default_tls: bool = False) -> None:
    security = (params.get("security") or params.get("tls") or "").lower()
    tls_enabled = default_tls or security in {"tls", "reality"} or parse_bool(params.get("tls"))
    if tls_enabled:
        proxy["tls"] = True

    servername = params.get("sni") or params.get("peer") or params.get("servername")
    if servername:
        if proxy["type"] == "trojan":
            proxy["sni"] = servername
        else:
            proxy["servername"] = servername

    if parse_bool(params.get("allowInsecure")) or parse_bool(params.get("insecure")):
        proxy["skip-cert-verify"] = True

    fingerprint = params.get("fp") or params.get("client-fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint

    alpn = split_alpn(params.get("alpn"))
    if alpn:
        proxy["alpn"] = alpn

    if security == "reality":
        proxy["tls"] = True
        reality_opts: dict[str, Any] = {}
        if params.get("pbk"):
            reality_opts["public-key"] = params["pbk"]
        if params.get("sid"):
            reality_opts["short-id"] = params["sid"]
        if reality_opts:
            proxy["reality-opts"] = reality_opts


def add_transport_fields(proxy: dict[str, Any], params: dict[str, str], network: str) -> None:
    if network == "tcp":
        header_type = params.get("headerType") or params.get("header-type")
        if header_type and header_type != "none":
            proxy["tcp-opts"] = {"header-type": header_type}
        return

    if network == "ws":
        opts: dict[str, Any] = {}
        if params.get("path"):
            opts["path"] = params["path"]
        headers: dict[str, str] = {}
        if params.get("host"):
            headers["Host"] = params["host"]
        if headers:
            opts["headers"] = headers
        if opts:
            proxy["ws-opts"] = opts
        return

    if network == "grpc":
        service_name = params.get("serviceName") or params.get("service") or params.get("path")
        if service_name:
            proxy["grpc-opts"] = {"grpc-service-name": service_name.lstrip("/")}
        return

    if network == "h2":
        opts = {}
        if params.get("host"):
            opts["host"] = [item.strip() for item in params["host"].split(",") if item.strip()]
        if params.get("path"):
            opts["path"] = params["path"]
        if opts:
            proxy["h2-opts"] = opts
        return

    if network == "httpupgrade":
        opts = {}
        if params.get("path"):
            opts["path"] = params["path"]
        if params.get("host"):
            opts["host"] = params["host"]
        if opts:
            proxy["httpupgrade-opts"] = opts
        return

    if network == "xhttp":
        opts = {}
        if params.get("host"):
            opts["host"] = params["host"]
        if params.get("path"):
            opts["path"] = params["path"]
        if params.get("mode"):
            opts["mode"] = params["mode"]
        if params.get("extra"):
            try:
                extra = json.loads(params["extra"])
                padding = extra.get("xPaddingBytes") or extra.get("x-padding-bytes")
                if padding:
                    opts["x-padding-bytes"] = padding
            except json.JSONDecodeError:
                opts["extra"] = params["extra"]
        if opts:
            proxy["xhttp-opts"] = opts


def convert_vless(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    network = normalize_network(params.get("type"))
    proxy = {
        "name": node["name"],
        "type": "vless",
        "server": node["server"],
        "port": node["port"],
        "uuid": node["uuid"],
        "udp": True,
        "network": network,
    }
    if params.get("flow"):
        proxy["flow"] = params["flow"]
    add_tls_fields(proxy, params)
    add_transport_fields(proxy, params, network)
    return proxy


def convert_vmess(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    network = normalize_network(node.get("network") or params.get("type"))
    proxy = {
        "name": node["name"],
        "type": "vmess",
        "server": node["server"],
        "port": node["port"],
        "uuid": node["uuid"],
        "alterId": node.get("alter_id", 0),
        "cipher": node.get("cipher") or "auto",
        "udp": True,
        "network": network,
    }
    add_tls_fields(proxy, params)
    add_transport_fields(proxy, params, network)
    return proxy


def parse_plugin_opts(raw: str) -> dict[str, Any]:
    opts: dict[str, Any] = {}
    for item in raw.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            opts[key.strip()] = value.strip()
        else:
            opts[item] = True
    return opts


def parse_ss_plugin(raw: str) -> tuple[str, dict[str, Any]]:
    parts = [part for part in raw.split(";") if part]
    plugin = parts[0] if parts else raw
    opts = parse_plugin_opts(";".join(parts[1:])) if len(parts) > 1 else {}
    if plugin == "v2ray-plugin" and "mode" not in opts:
        opts["mode"] = "websocket"
    return plugin, opts


def convert_ss(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    proxy = {
        "name": node["name"],
        "type": "ss",
        "server": node["server"],
        "port": node["port"],
        "cipher": node["cipher"],
        "password": node["password"],
        "udp": True,
    }
    if params.get("plugin"):
        plugin, plugin_opts = parse_ss_plugin(params["plugin"])
        proxy["plugin"] = plugin
        if plugin_opts:
            proxy["plugin-opts"] = plugin_opts
    elif params.get("plugin-opts"):
        proxy["plugin-opts"] = parse_plugin_opts(params["plugin-opts"])
    return proxy


def convert_trojan(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    network = normalize_network(params.get("type"))
    proxy = {
        "name": node["name"],
        "type": "trojan",
        "server": node["server"],
        "port": node["port"],
        "password": node["password"],
        "udp": True,
    }
    if network != "tcp":
        proxy["network"] = network
    add_tls_fields(proxy, params, default_tls=True)
    add_transport_fields(proxy, params, network)
    return proxy



def add_modern_tls_fields(proxy: dict[str, Any], params: dict[str, str]) -> None:
    """Add Mihomo TLS fields used by Hysteria2, TUIC and AnyTLS."""
    # 这三种协议本身均基于 TLS；Mihomo 标准节点需要显式标记 tls。
    proxy["tls"] = True

    sni = params.get("sni") or params.get("peer") or params.get("servername")
    if sni:
        proxy["sni"] = sni

    if parse_bool(params.get("allowInsecure")) or parse_bool(params.get("insecure")):
        proxy["skip-cert-verify"] = True

    alpn = split_alpn(params.get("alpn"))
    if alpn:
        proxy["alpn"] = alpn

    fingerprint = params.get("fp") or params.get("client-fingerprint")
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint

    ech_config = (
        params.get("ech-config")
        or params.get("ech_config")
        or params.get("echConfig")
        or params.get("ech")
    )
    if ech_config:
        # parse_qsl 会把未转义的“+”解释为空格；ECH 配置是 Base64，需还原。
        proxy["ech-opts"] = {"enable": True, "config": ech_config.replace(" ", "+")}


def convert_hysteria2(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    proxy = {
        "name": node["name"],
        "type": "hysteria2",
        "server": node["server"],
        "port": node["port"],
        "password": node["password"],
    }
    add_modern_tls_fields(proxy, params)

    # 兼容常见 Hysteria2 分享链接参数。
    if params.get("ports"):
        proxy["ports"] = params["ports"]
    hop_interval = params.get("hop-interval") or params.get("hop_interval")
    if hop_interval:
        proxy["hop-interval"] = hop_interval
    for query_keys, yaml_key in (
        (("up", "upmbps"), "up"),
        (("down", "downmbps"), "down"),
    ):
        value = next((params[key] for key in query_keys if params.get(key)), None)
        if value is not None:
            try:
                proxy[yaml_key] = int(value)
            except ValueError as exc:
                raise ValueError(f"invalid Hysteria2 {yaml_key}: {value}") from exc
    if params.get("obfs"):
        proxy["obfs"] = params["obfs"]
    obfs_password = params.get("obfs-password") or params.get("obfs_password")
    if obfs_password:
        proxy["obfs-password"] = obfs_password
    if params.get("pinSHA256"):
        proxy["fingerprint"] = params["pinSHA256"]
    return proxy


def convert_tuic(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    proxy = {
        "name": node["name"],
        "type": "tuic",
        "server": node["server"],
        "port": node["port"],
        "uuid": node["uuid"],
        "password": node["password"],
    }
    add_modern_tls_fields(proxy, params)

    congestion = params.get("congestion_control") or params.get("congestion-controller")
    if congestion:
        proxy["congestion-controller"] = congestion
    udp_mode = params.get("udp_relay_mode") or params.get("udp-relay-mode")
    if udp_mode:
        proxy["udp-relay-mode"] = udp_mode
    if parse_bool(params.get("reduce_rtt")) or parse_bool(params.get("reduce-rtt")):
        proxy["reduce-rtt"] = True
    if parse_bool(params.get("disable_sni")) or parse_bool(params.get("disable-sni")):
        proxy["disable-sni"] = True
    return proxy


def convert_anytls(node: dict[str, Any]) -> dict[str, Any]:
    params = node["params"]
    proxy = {
        "name": node["name"],
        "type": "anytls",
        "server": node["server"],
        "port": node["port"],
        "password": node["password"],
    }
    add_modern_tls_fields(proxy, params)

    for query_key, yaml_key in (
        ("idle-session-check-interval", "idle-session-check-interval"),
        ("idle-session-timeout", "idle-session-timeout"),
        ("min-idle-session", "min-idle-session"),
    ):
        if params.get(query_key):
            try:
                proxy[yaml_key] = int(params[query_key])
            except ValueError as exc:
                raise ValueError(f"invalid AnyTLS {query_key}: {params[query_key]}") from exc
    return proxy


def convert_node(node: dict[str, Any]) -> dict[str, Any]:
    if node["type"] == "vless":
        return convert_vless(node)
    if node["type"] == "vmess":
        return convert_vmess(node)
    if node["type"] == "ss":
        return convert_ss(node)
    if node["type"] == "trojan":
        return convert_trojan(node)
    if node["type"] == "hysteria2":
        return convert_hysteria2(node)
    if node["type"] == "tuic":
        return convert_tuic(node)
    if node["type"] == "anytls":
        return convert_anytls(node)
    raise ValueError(f"unsupported node type: {node['type']}")


def make_unique_names(proxies: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, int] = {}
    names: list[str] = []
    for proxy in proxies:
        base = str(proxy["name"]).strip() or f"{proxy['type']}-{proxy['server']}:{proxy['port']}"
        count = seen.get(base, 0)
        seen[base] = count + 1
        name = base if count == 0 else f"{base}-{count + 1}"
        proxy["name"] = name
        names.append(name)
    return names



SCRIPT_DIR = Path(__file__).resolve().parent


def parse_lines(lines: Any) -> tuple[list[dict[str, Any]], list[str]]:
    proxies: list[dict[str, Any]] = []
    warnings: list[str] = []
    for line_no, raw in enumerate(lines, 1):
        line = str(raw).strip()
        if not line or line.startswith("#"):
            continue
        try:
            proxies.append(convert_node(parse_node(line)))
        except Exception as exc:
            warnings.append(f"第 {line_no} 行：{exc}")
    make_unique_names(proxies)
    return proxies, warnings


def dump_proxy_block(proxies: list[dict[str, Any]]) -> str:
    """Serialize only the list entries that belong below the top-level proxies key."""
    dumped = yaml.dump(
        proxies,
        Dumper=NoAliasDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=4096,
    ).rstrip()
    return "\n".join("  " + line for line in dumped.splitlines())


def inject_proxies(template_text: str, proxies: list[dict[str, Any]]) -> str:
    """Replace the complete top-level proxies section and preserve all other YAML text/comments."""
    if not proxies:
        raise ValueError("没有成功解析任何节点，请检查输入内容。")
    lines = template_text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^proxies\s*:\s*(?:#.*)?$", line)), None)
    if start is None:
        raise ValueError("基础 YAML 中未找到顶层 proxies: 配置项。")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line and not line[0].isspace() and re.match(r"^[A-Za-z0-9_-]+\s*:", line):
            end = i
            break
    replacement = ["proxies:"] + dump_proxy_block(proxies).splitlines() + [""]
    merged = lines[:start] + replacement + lines[end:]
    return "\n".join(merged).rstrip() + "\n"


def dated_output_name() -> str:
    return f"clash_{date.today().strftime('%Y-%m-%d')}.yaml"



def discover_txt() -> Path:
    files = sorted(SCRIPT_DIR.glob("*.txt"))
    if not files:
        raise FileNotFoundError(f"脚本目录中未找到 txt 文件：{SCRIPT_DIR}")
    for name in ("sub.txt", "vless.txt", "nodes.txt"):
        path = SCRIPT_DIR / name
        if path in files:
            return path
    if len(files) > 1:
        print(f"[提示] 找到多个 txt 文件，使用：{files[0].name}")
    return files[0]


def discover_yaml(output_file: Path) -> Path:
    preferred = SCRIPT_DIR / "clash_rules.yaml"
    if preferred.is_file():
        return preferred
    files = sorted(p for p in SCRIPT_DIR.glob("*.yaml") if p.resolve() != output_file.resolve())
    files += sorted(p for p in SCRIPT_DIR.glob("*.yml") if p.resolve() != output_file.resolve())
    if not files:
        raise FileNotFoundError(f"脚本目录中未找到 YAML 基础配置：{SCRIPT_DIR}")
    if len(files) > 1:
        print(f"[提示] 找到多个 YAML 文件，使用：{files[0].name}")
    return files[0]


def main() -> int:
    output_file = SCRIPT_DIR / dated_output_name()
    try:
        txt_file = discover_txt()
        yaml_file = discover_yaml(output_file)
        proxies, warnings = parse_lines(txt_file.read_text(encoding="utf-8-sig").splitlines())
        result = inject_proxies(yaml_file.read_text(encoding="utf-8-sig"), proxies)
        output_file.write_text(result, encoding="utf-8")
    except Exception as exc:
        print(f"[错误] {exc}")
        return 1

    print(f"[完成] 输入节点：{txt_file.name}")
    print(f"[完成] 基础配置：{yaml_file.name}")
    print(f"[完成] 成功转换：{len(proxies)} 条")
    print(f"[完成] 解析警告：{len(warnings)} 条")
    for warning in warnings:
        print(f"[警告] {warning}")
    print(f"[完成] 输出文件：{output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
