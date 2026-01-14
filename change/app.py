import streamlit as st
import json
import base64
import urllib.parse
import os
import requests
import uuid


# ================= 核心处理逻辑 =================

def safe_base64_decode(s):
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(s).decode('utf-8')
    except:
        return base64.b64decode(s).decode('utf-8')


def parse_vmess(url_body):
    try:
        json_str = safe_base64_decode(url_body)
        data = json.loads(json_str)
        # 确保名称正确解码
        name = data.get("ps", "vmess")
        proxy = {
            "name": name,
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port")),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "network": data.get("net", "ws"),
            "tls": True if data.get("tls") else False,
            "udp": True,
            "skip-cert-verify": True if data.get("verify_cert") == False else False
        }
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", data.get("add"))}
            }
        return proxy
    except Exception:
        return None


def parse_vless(parsed_url):
    params = urllib.parse.parse_qs(parsed_url.query)
    network = params.get("type", ["tcp"])[0]

    # --- 修复乱码点：强制处理 fragment 的编码 ---
    raw_name = parsed_url.fragment
    name = urllib.parse.unquote(raw_name) if raw_name else "vless_node"

    proxy = {
        "name": name,
        "type": "vless",
        "server": parsed_url.hostname,
        "port": parsed_url.port,
        "uuid": parsed_url.username,
        "udp": True,
        "tls": True,
        "network": network,
        "servername": params.get("sni", [""])[0],
        "skip-cert-verify": True if params.get("allowInsecure", ["0"])[0] == "1" else False,
    }
    if network == "ws":
        host = params.get("host", [""])[0]
        if not host: host = proxy["servername"] or proxy["server"]
        proxy["ws-opts"] = {
            "path": params.get("path", ["/"])[0],
            "headers": {"Host": host}
        }
    if network == "tcp":
        flow = params.get("flow", [""])[0]
        if flow: proxy["flow"] = flow
    if "fp" in params:
        proxy["client-fingerprint"] = params["fp"][0]
    else:
        proxy["client-fingerprint"] = "chrome"
    if params.get("security", [""])[0] == "reality":
        proxy["reality-opts"] = {"public-key": params.get("pbk", [""])[0]}
        sid = params.get("sid", params.get("shortId", params.get("short-id", [])))
        if sid: proxy["reality-opts"]["short-id"] = sid[0]
        if not proxy["servername"]: proxy["servername"] = params.get("sni", [""])[0]
    return proxy


def parse_hysteria2(parsed_url):
    params = urllib.parse.parse_qs(parsed_url.query)
    name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else "hysteria2_node"
    return {
        "name": name,
        "type": "hysteria2",
        "server": parsed_url.hostname,
        "port": parsed_url.port,
        "password": parsed_url.username,
        "sni": params.get("sni", [""])[0],
        "skip-cert-verify": True if params.get("insecure", ["0"])[0] == "1" else False,
        "udp": True
    }


def parse_tuic(parsed_url):
    params = urllib.parse.parse_qs(parsed_url.query)
    user_info = parsed_url.username.split(':') if parsed_url.username else ["", ""]
    name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else "tuic_node"
    proxy = {
        "name": name,
        "type": "tuic",
        "server": parsed_url.hostname,
        "port": parsed_url.port,
        "uuid": user_info[0],
        "password": user_info[1] if len(user_info) > 1 else "",
        "sni": params.get("sni", [""])[0],
        "udp-relay-mode": "native",
        "congestion-controller": params.get("congestion_control", ["bbr"])[0],
        "skip-cert-verify": True if params.get("insecure", ["0"])[0] == "1" else False,
        "disable-sni": True,
        "udp": True
    }
    if "alpn" in params: proxy["alpn"] = [params["alpn"][0]]
    return proxy


def generate_yaml(proxies, rules_content, source_url=""):
    proxy_names = [p['name'] for p in proxies]
    header_info = f"# Source Subscription: {source_url}\n" if source_url else ""
    yaml_content = f"""{header_info}mixed-port: 7890
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
proxies:
"""
    for p in proxies:
        yaml_content += f"  - name: \"{p['name']}\"\n"  # 增加双引号防止YAML解析错误
        yaml_content += f"    type: {p['type']}\n"
        yaml_content += f"    server: {p['server']}\n"
        yaml_content += f"    port: {p['port']}\n"
        for key in ["uuid", "password", "udp", "tls", "flow", "servername", "sni", "client-fingerprint", "network",
                    "alterId", "cipher", "skip-cert-verify", "udp-relay-mode", "congestion-controller", "disable-sni"]:
            if key in p:
                val = str(p[key]).lower() if isinstance(p[key], bool) else p[key]
                yaml_content += f"    {key}: {val}\n"
        if "ws-opts" in p:
            yaml_content += f"    ws-opts:\n      path: {p['ws-opts']['path']}\n      headers:\n        Host: {p['ws-opts']['headers']['Host']}\n"
        if "reality-opts" in p:
            yaml_content += f"    reality-opts:\n      public-key: {p['reality-opts']['public-key']}\n"
            if "short-id" in p['reality-opts']: yaml_content += f"      short-id: {p['reality-opts']['short-id']}\n"
        if "alpn" in p:
            yaml_content += f"    alpn:\n"
            for a in p['alpn']: yaml_content += f"      - {a}\n"
    yaml_content += "proxy-groups:\n"
    groups = [
        {"name": "🚀 节点选择", "type": "select", "special": ["♻️ 自动选择", "DIRECT"]},
        {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300,
         "tolerance": 50, "special": []},
        {"name": "🌍 国外媒体", "type": "select", "special": ["🚀 节点选择", "♻️ 自动选择", "🎯 全球直连"]},
        {"name": "📲 电报信息", "type": "select", "special": ["🚀 节点选择", "🎯 全球直连"]},
        {"name": "Ⓜ️ 微软服务", "type": "select", "special": ["🎯 全球直连", "🚀 节点选择"]},
        {"name": "🍎 苹果服务", "type": "select", "special": ["🚀 节点选择", "🎯 全球直连"]},
        {"name": "📢 谷歌FCM", "type": "select", "special": ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择"]},
        {"name": "🎯 全球直连", "type": "select", "base": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"], "no_proxies": True},
        {"name": "🛑 全球拦截", "type": "select", "base": ["REJECT", "DIRECT"], "no_proxies": True},
        {"name": "🍃 应用净化", "type": "select", "base": ["REJECT", "DIRECT"], "no_proxies": True},
        {"name": "🐟 漏网之鱼", "type": "select", "special": ["🚀 节点选择", "🎯 全球直连", "♻️ 自动选择"]},
    ]
    for g in groups:
        yaml_content += f"  - name: \"{g['name']}\"\n    type: {g['type']}\n"
        if "url" in g: yaml_content += f"    url: {g['url']}\n    interval: {g['interval']}\n    tolerance: {g['tolerance']}\n"
        yaml_content += f"    proxies:\n"
        if "base" in g:
            for b in g["base"]: yaml_content += f"      - \"{b}\"\n"
        if "special" in g:
            for s in g["special"]: yaml_content += f"      - \"{s}\"\n"
        if not g.get("no_proxies", False):
            for name in proxy_names: yaml_content += f"      - \"{name}\"\n"
    yaml_content += "rules:\n" + rules_content
    return yaml_content


# ================= 网页界面逻辑 =================

st.set_page_config(page_title="V2Ray 转 Clash", page_icon="🔄")
st.title("🔄 V2Ray 链接转 Clash Meta 配置")
col1, col2 = st.columns(2)
with col1:
    nodes_file = st.file_uploader("1. 上传节点文件 (txt)", type=['txt'])
with col2:
    rules_file = st.file_uploader("2. 上传规则文件 (可选)", type=['txt'])

subscription_url = st.text_input("🔗 或者输入订阅链接 (URL)", placeholder="https://...")

# 固定服务器地址
server_host = "http://ip.padaro.top:8501"

if st.button("开始转换", type="primary"):
    nodes_content = ""
    current_source = ""
    if subscription_url:
        current_source = subscription_url.strip()
        try:
            with st.spinner("🚀 正在请求订阅数据..."):
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
                resp = requests.get(current_source, headers=headers, timeout=15)
                resp.raise_for_status()
                raw_content = resp.text.strip()
                try:
                    missing_padding = len(raw_content) % 4
                    if missing_padding: raw_content += '=' * (4 - missing_padding)
                    nodes_content = base64.b64decode(raw_content).decode('utf-8')
                except:
                    try:
                        nodes_content = base64.urlsafe_b64decode(raw_content).decode('utf-8')
                    except:
                        nodes_content = raw_content
                st.success("✅ 订阅获取并解析成功！")
        except Exception as e:
            st.error(f"❌ 获取订阅失败: {e}")
            st.stop()
    elif nodes_file:
        nodes_content = nodes_file.getvalue().decode("utf-8")
        current_source = nodes_file.name
    else:
        st.error("请上传节点文件或输入订阅链接！")
        st.stop()

    rules_content = ""
    if rules_file:
        rules_content = rules_file.getvalue().decode("utf-8")
    elif os.path.exists('rules.txt'):
        with open('rules.txt', 'r', encoding='utf-8') as f:
            rules_content = f.read()

    proxies = []
    name_counter = {}
    for line in nodes_content.splitlines():
        line = line.strip()
        if not line: continue
        p = None
        try:
            if line.startswith("vmess://"):
                p = parse_vmess(line[8:])
            elif line.startswith("vless://"):
                p = parse_vless(urllib.parse.urlparse(line))
            elif line.startswith("hysteria2://"):
                p = parse_hysteria2(urllib.parse.urlparse(line))
            elif line.startswith("tuic://"):
                p = parse_tuic(urllib.parse.urlparse(line))
            if p:
                o_name = p['name']
                if o_name in name_counter:
                    name_counter[o_name] += 1
                    p['name'] = f"{o_name}_{name_counter[o_name]}"
                else:
                    name_counter[o_name] = 0
                proxies.append(p)
        except:
            continue

    if not proxies:
        st.error("❌ 未识别到有效节点")
    else:
        final_yaml = generate_yaml(proxies, rules_content, current_source)

        # 静态文件处理
        static_dir = "static"
        if not os.path.exists(static_dir): os.makedirs(static_dir)
        random_filename = f"config_{uuid.uuid4().hex[:8]}.yaml"
        file_path = os.path.join(static_dir, random_filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(final_yaml)

        # --- 修复路径逻辑：不加 /app ---
        download_url = f"{server_host}/static/{random_filename}"

        st.markdown("### 📋 订阅链接 (点击复制)")
        st.code(download_url, language="text")
        st.download_button("📥 下载本地文件", data=final_yaml, file_name="config.yaml")