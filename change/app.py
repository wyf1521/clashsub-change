import streamlit as st
import json
import base64
import urllib.parse
import os
import requests  # 新增：用于请求网络链接


# ================= 核心处理逻辑 (保持不变) =================

def safe_base64_decode(s):
    """
    用于解析 vmess:// 后面的 base64 字符串
    """
    s = s.strip()
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(s).decode('utf-8')


def parse_vmess(url_body):
    try:
        json_str = safe_base64_decode(url_body)
        data = json.loads(json_str)
        proxy = {
            "name": data.get("ps", "vmess"),
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
    proxy = {
        "name": urllib.parse.unquote(parsed_url.fragment),
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
    return {
        "name": urllib.parse.unquote(parsed_url.fragment),
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
    proxy = {
        "name": urllib.parse.unquote(parsed_url.fragment),
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


def generate_yaml(proxies, rules_content):
    proxy_names = [p['name'] for p in proxies]
    yaml_content = """mixed-port: 7890
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
proxies:
"""
    for p in proxies:
        yaml_content += f"  - name: {p['name']}\n"
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
        yaml_content += f"  - name: {g['name']}\n    type: {g['type']}\n"
        if "url" in g: yaml_content += f"    url: {g['url']}\n    interval: {g['interval']}\n    tolerance: {g['tolerance']}\n"
        yaml_content += f"    proxies:\n"
        if "base" in g:
            for b in g["base"]: yaml_content += f"      - {b}\n"
        if "special" in g:
            for s in g["special"]: yaml_content += f"      - {s}\n"
        if not g.get("no_proxies", False):
            for name in proxy_names: yaml_content += f"      - {name}\n"

    yaml_content += "rules:\n" + rules_content
    return yaml_content


# ================= 网页界面逻辑 =================

st.set_page_config(page_title="V2Ray 转 Clash", page_icon="🔄")

st.title("🔄 V2Ray 链接转 Clash Meta 配置")
st.markdown("上传你的节点列表文件，或者直接输入订阅链接。")

# 布局：文件上传区域
col1, col2 = st.columns(2)
with col1:
    nodes_file = st.file_uploader("1. 上传节点文件 (txt)", type=['txt'], help="每行一个 vmess/vless 链接")
with col2:
    rules_file = st.file_uploader("2. 上传规则文件 (可选)", type=['txt'], help="留空则读取服务器本地 rules.txt")

# 新增：订阅链接输入框
subscription_url = st.text_input("🔗 或者输入订阅链接 (URL)", placeholder="https://example.com/subscribe?token=...",
                                 help="输入机场或面板的订阅链接，自动抓取并 Base64 解码")

# 备用极简规则
fallback_rules = """  - GEOIP,CN,🎯 全球直连
  - MATCH,🐟 漏网之鱼
"""

if st.button("开始转换", type="primary"):
    nodes_content = ""

    # === 1. 获取节点内容 (优先处理订阅链接) ===
    if subscription_url:
        try:
            with st.spinner("🚀 正在请求订阅数据..."):
                # 模拟浏览器 User-Agent，防止部分机场拦截 Python 请求
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
                resp = requests.get(subscription_url.strip(), headers=headers, timeout=15)
                resp.raise_for_status()
                raw_content = resp.text.strip()

                # Base64 解码逻辑
                try:
                    # 自动补全 Base64 缺失的 Padding
                    missing_padding = len(raw_content) % 4
                    if missing_padding:
                        raw_content += '=' * (4 - missing_padding)

                    # 尝试标准解码
                    nodes_content = base64.b64decode(raw_content).decode('utf-8')
                except Exception as e:
                    # 如果标准解码失败，尝试 URL-safe 解码，或直接假设是明文
                    try:
                        nodes_content = base64.urlsafe_b64decode(raw_content).decode('utf-8')
                    except Exception:
                        # 既不是标准Base64也不是URLSafeBase64，可能直接是明文列表
                        nodes_content = raw_content
                        st.warning("⚠️ 内容似乎不是 Base64 编码，尝试直接解析...")

                st.success("✅ 订阅获取并解析成功！")
        except Exception as e:
            st.error(f"❌ 获取订阅失败: {e}")
            st.stop()

    # === 2. 如果没输链接，检查上传的文件 ===
    elif nodes_file:
        nodes_content = nodes_file.getvalue().decode("utf-8")

    else:
        st.error("请上传节点文件或输入订阅链接！")
        st.stop()

    # === 3. 规则文件加载逻辑 ===
    if rules_file:
        rules_content = rules_file.getvalue().decode("utf-8")
        st.success("已使用您上传的规则文件。")
    elif os.path.exists('rules.txt'):
        try:
            with open('rules.txt', 'r', encoding='utf-8') as f:
                rules_content = f.read()
            st.info("检测到未上传规则，已自动加载服务器本地 rules.txt。")
        except Exception as e:
            st.error(f"本地 rules.txt 读取失败: {e}")
            rules_content = fallback_rules
    else:
        st.warning("⚠️ 未上传规则文件，且服务器本地未找到 rules.txt，将使用内置极简规则。")
        rules_content = fallback_rules

    # === 4. 处理节点解析 ===
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
                # 重名检测
                original_name = p['name']
                if original_name in name_counter:
                    name_counter[original_name] += 1
                    p['name'] = f"{original_name}_{name_counter[original_name]}"
                else:
                    name_counter[original_name] = 0

                proxies.append(p)
        except Exception:
            continue

    if not proxies:
        st.error("❌ 未能识别到有效的节点链接，请检查订阅内容或文件。")
    else:
        final_yaml = generate_yaml(proxies, rules_content)

        st.success(f"🎉 转换成功！共包含 {len(proxies)} 个节点。")

        st.download_button(
            label="下载 config.yaml",
            data=final_yaml,
            file_name="config.yaml",
            mime="text/yaml"
        )

        with st.expander("预览生成的内容"):
            st.code(final_yaml, language="yaml")
