import streamlit as st
import json
import base64
import urllib.parse
import os
import requests
import uuid


ALLOWED_PREFIXES = ("vmess://", "vless://", "hysteria2://", "tuic://")


def safe_base64_decode(s: str) -> str:
    """安全的 Base64 解码，处理填充和替换；失败则返回原字符串"""
    if not s:
        return ""
    s = s.strip().replace("-", "+").replace("_", "/")
    missing_padding = len(s) % 4
    if missing_padding:
        s += "=" * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except Exception:
        try:
            return base64.b64decode(s).decode("utf-8")
        except Exception:
            return s


def safe_name_decode(name: str) -> str:
    if not name:
        return "Unknown_Node"
    try:
        decoded = urllib.parse.unquote(name)
        decoded = urllib.parse.unquote(decoded)
        return decoded
    except Exception:
        return name


def normalize_nodes_text(text: str) -> str:
    """把订阅里常见的 | 分隔也统一成换行，方便后续逐行处理"""
    if not text:
        return ""
    return text.replace("|", "\n")


def filter_valid_nodes_lines(text: str):
    """
    过滤 + 统计：
    - valid_lines：合法行（非空且以允许协议开头）
    - invalids：非法行 (行号, 内容)
    - stats：统计信息
    """
    valid_lines = []
    invalids = []

    total_nonempty = 0
    proto_count = {"vmess": 0, "vless": 0, "hysteria2": 0, "tuic": 0}

    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        total_nonempty += 1

        if line.startswith("vmess://"):
            proto_count["vmess"] += 1
            valid_lines.append(line)
        elif line.startswith("vless://"):
            proto_count["vless"] += 1
            valid_lines.append(line)
        elif line.startswith("hysteria2://"):
            proto_count["hysteria2"] += 1
            valid_lines.append(line)
        elif line.startswith("tuic://"):
            proto_count["tuic"] += 1
            valid_lines.append(line)
        else:
            invalids.append((idx, line))

    stats = {
        "total_nonempty": total_nonempty,
        "valid": len(valid_lines),
        "invalid": len(invalids),
        "proto_count": proto_count,
    }
    return valid_lines, invalids, stats


def dedupe_lines_keep_first(lines):
    """
    去重：按整行去重（strip 后）
    - 返回：deduped_lines, dup_count
    """
    seen = set()
    deduped = []
    dup_count = 0
    for line in lines:
        key = line.strip()
        if not key:
            continue
        if key in seen:
            dup_count += 1
            continue
        seen.add(key)
        deduped.append(line)
    return deduped, dup_count


def parse_vmess(url_body: str):
    try:
        json_str = safe_base64_decode(url_body)
        data = json.loads(json_str)

        raw_name = data.get("ps", "vmess")
        name = safe_name_decode(raw_name)

        proxy = {
            "name": name,
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port")),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "network": data.get("net", "ws"),
            "tls": True if data.get("tls") == "tls" or data.get("tls") is True else False,
            "udp": True,
            "skip-cert-verify": True if data.get("verify_cert") is False else False,
        }
        if proxy["network"] == "ws":
            proxy["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {"Host": data.get("host", data.get("add"))},
            }
        return proxy
    except Exception:
        return None


def parse_vless(parsed_url):
    params = urllib.parse.parse_qs(parsed_url.query)
    network = params.get("type", ["tcp"])[0]

    raw_name = parsed_url.fragment
    name = safe_name_decode(raw_name) if raw_name else "vless_node"

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
        if not host:
            host = proxy["servername"] or proxy["server"]
        proxy["ws-opts"] = {
            "path": params.get("path", ["/"])[0],
            "headers": {"Host": host},
        }
    if network == "tcp":
        flow = params.get("flow", [""])[0]
        if flow:
            proxy["flow"] = flow
    if "fp" in params:
        proxy["client-fingerprint"] = params["fp"][0]
    else:
        proxy["client-fingerprint"] = "chrome"
    if params.get("security", [""])[0] == "reality":
        proxy["reality-opts"] = {"public-key": params.get("pbk", [""])[0]}
        sid = params.get("sid", params.get("shortId", params.get("short-id", [])))
        if sid:
            proxy["reality-opts"]["short-id"] = sid[0]
        if not proxy["servername"]:
            proxy["servername"] = params.get("sni", [""])[0]
    return proxy


def parse_hysteria2(parsed_url):
    params = urllib.parse.parse_qs(parsed_url.query)
    name = safe_name_decode(parsed_url.fragment) if parsed_url.fragment else "hysteria2_node"
    return {
        "name": name,
        "type": "hysteria2",
        "server": parsed_url.hostname,
        "port": parsed_url.port,
        "password": parsed_url.username,
        "sni": params.get("sni", [""])[0],
        "skip-cert-verify": True if params.get("insecure", ["0"])[0] == "1" else False,
        "udp": True,
    }


def parse_tuic(parsed_url):
    params = urllib.parse.parse_qs(parsed_url.query)
    user_info = parsed_url.username.split(":") if parsed_url.username else ["", ""]
    name = safe_name_decode(parsed_url.fragment) if parsed_url.fragment else "tuic_node"
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
        "udp": True,
    }
    if "alpn" in params:
        proxy["alpn"] = [params["alpn"][0]]
    return proxy


def generate_yaml(proxies, rules_content, source_url=""):
    proxy_names = []
    for p in proxies:
        safe_n = p["name"].replace('"', "").replace("'", "").strip()
        p["name"] = safe_n
        proxy_names.append(safe_n)

    header_info = f"# Source Subscription: {source_url}\n" if source_url else ""
    yaml_content = f"""{header_info}mixed-port: 7890
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
proxies:
"""
    for p in proxies:
        yaml_content += f'  - name: "{p["name"]}"\n'
        yaml_content += f"    type: {p['type']}\n"
        yaml_content += f"    server: {p['server']}\n"
        yaml_content += f"    port: {p['port']}\n"
        for key in [
            "uuid",
            "password",
            "udp",
            "tls",
            "flow",
            "servername",
            "sni",
            "client-fingerprint",
            "network",
            "alterId",
            "cipher",
            "skip-cert-verify",
            "udp-relay-mode",
            "congestion-controller",
            "disable-sni",
        ]:
            if key in p:
                val = str(p[key]).lower() if isinstance(p[key], bool) else p[key]
                yaml_content += f"    {key}: {val}\n"

        if "ws-opts" in p:
            yaml_content += (
                "    ws-opts:\n"
                f'      path: "{p["ws-opts"]["path"]}"\n'
                "      headers:\n"
                f'        Host: {p["ws-opts"]["headers"]["Host"]}\n'
            )
        if "reality-opts" in p:
            yaml_content += "    reality-opts:\n"
            yaml_content += f'      public-key: {p["reality-opts"]["public-key"]}\n'
            if "short-id" in p["reality-opts"]:
                yaml_content += f'      short-id: {p["reality-opts"]["short-id"]}\n'
        if "alpn" in p:
            yaml_content += "    alpn:\n"
            for a in p["alpn"]:
                yaml_content += f"      - {a}\n"

    yaml_content += "proxy-groups:\n"

    groups = [
        {"name": "🚀 节点选择", "type": "select", "special": ["♻️ 自动选择", "DIRECT"]},
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "special": [],
        },
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
        yaml_content += f'  - name: "{g["name"]}"\n'
        yaml_content += f"    type: {g['type']}\n"
        if "url" in g:
            yaml_content += f"    url: {g['url']}\n"
            yaml_content += f"    interval: {g['interval']}\n"
            yaml_content += f"    tolerance: {g['tolerance']}\n"

        yaml_content += "    proxies:\n"
        if "base" in g:
            for b in g["base"]:
                yaml_content += f'      - "{b}"\n'
        if "special" in g:
            for s in g["special"]:
                yaml_content += f'      - "{s}"\n'
        if not g.get("no_proxies", False):
            for name in proxy_names:
                yaml_content += f'      - "{name}"\n'

    yaml_content += "rules:\n" + rules_content
    return yaml_content


# ================= 网页界面逻辑 =================

st.set_page_config(page_title="V2Ray 转 Clash", page_icon="🔄", layout="centered")

# ===== GitHub 项目入口（侧边栏）=====
st.sidebar.markdown("## 项目地址")
st.sidebar.markdown(
    """
    <a href="https://github.com/wyf1521/clashsub-change" target="_blank"
       style="display:flex;align-items:center;gap:8px;text-decoration:none;">
      <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" width="20">
      <span>wyf1521 / clashsub-change</span>
    </a>
    """,
    unsafe_allow_html=True,
)
st.sidebar.link_button("打开 GitHub", "https://github.com/wyf1521/clashsub-change")

st.title("🔄 V2Ray 链接转 Clash Meta 配置")
st.markdown("---")

col1, col2 = st.columns(2)
with col1:
    nodes_files = st.file_uploader("1. 上传节点文件 (txt，可多选)", type=["txt"], accept_multiple_files=True)
with col2:
    rules_file = st.file_uploader("2. 上传规则文件 (可选)", type=["txt"])

manual_nodes_text = st.text_area(
    "🧾 手动粘贴节点内容（优先级最高；每行一个链接，仅支持 vmess/vless/hysteria2/tuic）",
    placeholder="hysteria2://...\ntuic://...\nvmess://...\nvless://...",
    height=180,
)

subscription_urls_text = st.text_area(
    "🔗 输入订阅链接（优先级最低；可多行，每行一个）",
    placeholder="https://example.com/sub/...\nhttps://example2.com/sub/...",
    height=120,
)
subscription_urls = [u.strip() for u in subscription_urls_text.splitlines() if u.strip()]

# 注意：请确保服务器已配置静态文件服务
server_host = "http://ip.padaro.top:8501"

if st.button("开始转换", type="primary", use_container_width=True):
    sources = []
    contents = []

    # =========================================================
    # 顺序要求：手动输入（最前） -> 上传文件（其次） -> 订阅网址（最后）
    # =========================================================

    # --- 1) 手动粘贴（最高优先级）---
    if manual_nodes_text and manual_nodes_text.strip():
        text = normalize_nodes_text(manual_nodes_text)
        sources.append("manual_input")
        contents.append(text)

    # --- 2) 上传文件（其次）---
    if nodes_files:
        for f in nodes_files:
            try:
                text = f.getvalue().decode("utf-8", errors="ignore")
                text = normalize_nodes_text(text)
                if text.strip():
                    sources.append(f.name)
                    contents.append(text)
            except Exception as e:
                st.error(f"❌ 读取文件失败：{f.name}\n原因：{e}")

    # --- 3) 订阅链接（最后）---
    for url in subscription_urls:
        try:
            with st.spinner(f"🚀 正在请求订阅：{url}"):
                headers = {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    )
                }
                resp = requests.get(url, headers=headers, timeout=15)
                resp.raise_for_status()
                raw_content = resp.text.strip()

                decoded = safe_base64_decode(raw_content)

                decoded_n = normalize_nodes_text(decoded)
                raw_n = normalize_nodes_text(raw_content)

                # 选择“更像节点列表”的那个
                if any(p in decoded_n for p in ALLOWED_PREFIXES):
                    text = decoded_n
                else:
                    text = raw_n

                if text.strip():
                    sources.append(url)
                    contents.append(text)
        except Exception as e:
            st.error(f"❌ 获取订阅失败：{url}\n原因：{e}")

    if not contents:
        st.warning("⚠️ 请至少粘贴节点内容、上传节点文件，或输入订阅链接！")
        st.stop()

    # 合并（按上面 append 的顺序）
    nodes_content_raw = "\n".join(contents).strip()
    current_source = " | ".join(sources)

    # --- 过滤非法行（跳过 + 统计 + 提示）---
    valid_lines, invalids, stats = filter_valid_nodes_lines(nodes_content_raw)

    # --- 去重：保留第一次出现（因此优先级自然成立）---
    deduped_lines, dup_count = dedupe_lines_keep_first(valid_lines)

    # UI 统计
    st.info(
        f"📊 输入统计：非空行 {stats['total_nonempty']}，有效 {stats['valid']}，跳过 {stats['invalid']}，去重丢弃 {dup_count}。\n"
        f"协议分布：vmess {stats['proto_count']['vmess']} / "
        f"vless {stats['proto_count']['vless']} / "
        f"hysteria2 {stats['proto_count']['hysteria2']} / "
        f"tuic {stats['proto_count']['tuic']}"
    )

    if invalids:
        show_n = 20
        preview = "\n".join([f"第 {ln} 行：{txt[:200]}" for ln, txt in invalids[:show_n]])
        st.warning("⚠️ 已跳过不支持的行（只保留 vmess/vless/hysteria2/tuic 开头的行）")
        st.code(preview, language="text")
        if len(invalids) > show_n:
            st.caption(f"仅展示前 {show_n} 条，共 {len(invalids)} 条被跳过。")

    if dup_count > 0:
        st.warning(f"♻️ 已去重：发现并丢弃 {dup_count} 条重复节点行（保留优先级更高的首次出现）。")

    if not deduped_lines:
        st.error("❌ 没有任何有效节点行（全部被跳过或为空），请检查输入。")
        st.stop()

    nodes_content = "\n".join(deduped_lines)

    # --- 读取规则文件 ---
    rules_content = ""
    if rules_file:
        rules_content = rules_file.getvalue().decode("utf-8", errors="ignore")
    elif os.path.exists("rules.txt"):
        try:
            with open("rules.txt", "r", encoding="utf-8") as f:
                rules_content = f.read()
        except Exception:
            rules_content = ""

    # --- 解析节点（顺序 = nodes_content 顺序）---
    proxies = []
    name_counter = {}

    for line in nodes_content.splitlines():
        line = line.strip()
        if not line:
            continue

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
                o_name = p["name"]
                if o_name in name_counter:
                    name_counter[o_name] += 1
                    p["name"] = f"{o_name}_{name_counter[o_name]}"
                else:
                    name_counter[o_name] = 0
                proxies.append(p)
        except Exception:
            continue

    if not proxies:
        st.error("❌ 未识别到有效节点，请检查链接格式")
    else:
        final_yaml = generate_yaml(proxies, rules_content, current_source)

        static_dir = "static"
        if not os.path.exists(static_dir):
            os.makedirs(static_dir)

        random_filename = f"config_{uuid.uuid4().hex[:8]}.yaml"
        file_path = os.path.join(static_dir, random_filename)

        with open(file_path, "w", encoding="utf-8-sig") as f:
            f.write(final_yaml)

        download_url = f"{server_host}/app/static/{random_filename}"

        st.success(f"🎉 转换成功！共包含 {len(proxies)} 个节点")
        st.markdown("---")

        st.markdown("### 📋 订阅链接")
        st.info("请全选下方的链接进行复制：")

        st.text_input("订阅 URL", value=download_url)

        st.download_button(
            label="📥 下载 YAML 配置文件",
            data=final_yaml,
            file_name="clash_config.yaml",
            mime="text/yaml",
        )
