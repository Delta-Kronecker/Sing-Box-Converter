import os
import base64
import json
import requests
import re
from urllib.parse import urlparse, parse_qs, unquote, quote
from collections import OrderedDict
import uuid



def get_shadowsocks_template():
    return {
        "type": "shadowsocks", "tag": "", "server": "", "server_port": 0,
        "method": "", "password": ""
    }


def get_vmess_template():
    return {
        "type": "vmess", "tag": "", "server": "", "server_port": 0, "uuid": "",
        "security": "auto", "alter_id": 0, "transport": {
            "type": "", "path": "", "headers": {}, "service_name": ""
        },
        "tls": {
            "enabled": False, "server_name": "", "insecure": False, "alpn": []
        }
    }


def get_vless_template():
    return {
        "type": "vless", "tag": "", "server": "", "server_port": 0, "uuid": "",
        "flow": "", "packet_encoding": "xudp", "transport": {
            "type": "", "path": "", "headers": {}, "service_name": ""
        },
        "tls": {
            "enabled": False, "server_name": "", "insecure": False, "alpn": [],
            "reality": {"enabled": False, "public_key": "", "short_id": ""}
        }
    }


def get_trojan_template():
    return {
        "type": "trojan", "tag": "", "server": "", "server_port": 0, "password": "",
        "transport": {"type": "", "path": "", "headers": {}},
        "tls": {"enabled": False, "server_name": "", "insecure": False, "alpn": []}
    }


def get_hysteria2_template():
    return {
        "type": "hysteria2", "tag": "", "server": "", "server_port": 0, "password": "",
        "obfs": {"type": "", "password": ""},
        "tls": {"enabled": False, "server_name": "", "insecure": False, "alpn": []}
    }


def get_tuic_template():
    return {
        "type": "tuic", "tag": "", "server": "", "server_port": 0, "uuid": "", "password": "",
        "congestion_control": "bbr", "udp_relay_mode": "native", "zero_rtt_handshake": False,
        "heartbeat": "10s",
        "tls": {
            "enabled": False, "server_name": "", "insecure": False, "alpn": []
        }
    }



class SubStats:
    def __init__(self, url):
        self.url = url
        self.total_configs = 0
        self.unique_configs = 0
        self.duplicates = 0
        self.line_count = 0
        self.parse_errors = 0


def generate_config_key(bean):
    return f"{bean['type']}://{bean['server']}:{bean['server_port']}"


def read_file_text(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return ""


def write_file_text(path, text):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        return True
    except Exception as e:
        print(f"  Error saving: {path} ({e})")
        return False


def http_get(url):
    headers = {'User-Agent': 'ConfigCollector/1.0'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return {'data': response.content, 'error': ''}
    except requests.exceptions.RequestException as e:
        return {'data': b'', 'error': str(e)}


def decode_b64_if_valid(s):
    if not s or len(s) < 4:
        return ""

    s = s.strip()

    try:
        padding = '=' * (4 - len(s) % 4)
        decoded = base64.urlsafe_b64decode(s + padding).decode('utf-8')
        if decoded and len(decoded) > 0:
            return decoded
    except (ValueError, TypeError, UnicodeDecodeError):
        pass

    try:
        padding = '=' * (4 - len(s) % 4)
        decoded = base64.b64decode(s + padding).decode('utf-8')
        if decoded and len(decoded) > 0:
            return decoded
    except (ValueError, TypeError, UnicodeDecodeError):
        pass

    try:
        decoded = base64.b64decode(s).decode('utf-8')
        if decoded and len(decoded) > 0:
            return decoded
    except (ValueError, TypeError, UnicodeDecodeError):
        pass

    return ""


def sanitize_filename(url):
    filename = re.sub(r'https?://', '', url)
    return re.sub(r'[/:*?"<>|]', '_', filename)


def pre_parse_url(link):
    if '://' not in link:
        return link

    proto, rest = link.split('://', 1)
    if '@' in rest:
        parts = rest.split('@')
        userinfo = '@'.join(parts[:-1])
        hostinfo = parts[-1]
        userinfo = quote(userinfo, safe=':')
        return f"{proto}://{userinfo}@{hostinfo}"
    return link


def is_vless_disguised_as_ss(link):
    
    vless_indicators = [
        'security=',
        'encryption=none',
        'type=ws',
        'type=grpc',
        'type=tcp',
        'path=',
        'mode=gun',
        'mode=auto',
        'headerType=',
        'alpn=',
        'fp=',
        'sni=',
        'pbk=',  # reality public key
        'sid=',  # reality short id
        'flow='
    ]

    indicator_count = sum(1 for indicator in vless_indicators if indicator in link)

    has_uuid_format = False
    try:
        if '@' in link:
            userpart = link.split('://')[1].split('@')[0]
            if userpart.count('-') >= 4 and len(userpart) >= 32:
                has_uuid_format = True
    except:
        pass

    return indicator_count >= 2 or (indicator_count >= 1 and has_uuid_format)



def parse_single_link(link):
    link = link.strip()
    if not link or link.startswith('#'):
        return None

    link = pre_parse_url(link)

    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        if is_vless_disguised_as_ss(link):
            converted_link = link.replace("ss://", "vless://", 1)
            return parse_vless(converted_link)
        else:
            return parse_shadowsocks(link)
    if link.startswith("hy2://") or link.startswith("hysteria2://"):
        return parse_hysteria2(link)
    if link.startswith("tuic://"):
        return parse_tuic(link)

    return None


def parse_subscription(content, max_depth=5, current_depth=0):
    if current_depth >= max_depth:
        return [], 0, content

    decoded_content = decode_b64_if_valid(content.strip())
    if decoded_content and decoded_content != content.strip():
        protocols = ['vmess://', 'vless://', 'trojan://', 'ss://', 'hy2://', 'tuic://', 'hysteria2://']
        if any(proto in decoded_content for proto in protocols):
            return parse_subscription(decoded_content, max_depth, current_depth + 1)

    protocols_regex = ['vmess', 'vless', 'trojan', 'ss', 'hy2', 'tuic', 'hysteria2']

    pattern = r'(?:' + '|'.join(p + r'://[^\s\r\n]+' for p in protocols_regex) + ')'
    links = [match.group(0) for match in re.finditer(pattern, content, re.MULTILINE)]

    if not links:
        lines = content.splitlines()
        links = []
        for line in lines:
            line = line.strip()
            if any(line.startswith(p + '://') for p in protocols_regex):
                links.append(line)

    cleaned_links = []
    for link in links:
        link = link.strip().rstrip('\r\n\t ,;')
        link = link.strip('"\'')
        if link:
            cleaned_links.append(link)

    beans = []
    line_count = len(cleaned_links)
    parse_errors = 0

    for i, line in enumerate(cleaned_links):
        try:
            bean = parse_single_link(line)
            if bean:
                beans.append(bean)
            else:
                parse_errors += 1
        except Exception as e:
            parse_errors += 1
            if parse_errors <= 5: 
                print(f"    Parse error on line {i + 1}: {str(e)[:80]}")

    if parse_errors > 5:
        print(f"    ... and {parse_errors - 5} more parse errors")

    return beans, line_count, content


def parse_vmess(link):
    try:
        decoded_part = decode_b64_if_valid(link.replace("vmess://", ""))
        if not decoded_part:
            return None

        data = json.loads(decoded_part)

        bean = get_vmess_template()
        bean["tag"] = data.get("ps", "")
        bean["server"] = data.get("add", "")
        bean["server_port"] = int(data.get("port", 0))
        bean["uuid"] = data.get("id", "")
        bean["alter_id"] = int(data.get("aid", 0))
        bean["security"] = data.get("scy", "auto")

        net = data.get("net", "tcp")
        bean["transport"]["type"] = net
        if net == "ws":
            bean["transport"]["path"] = data.get("path", "")
            bean["transport"]["headers"]["Host"] = data.get("host", "")
        elif net == "grpc":
            bean["transport"]["service_name"] = data.get("serviceName", "")

        if data.get("tls") == "tls":
            bean["tls"]["enabled"] = True
            bean["tls"]["server_name"] = data.get("sni", "") or data.get("host", "")

        return bean
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        return None


def parse_vless(link):
    try:
        url = urlparse(link)
        query = parse_qs(url.query)

        bean = get_vless_template()
        bean["tag"] = unquote(url.fragment) if url.fragment else ""
        bean["server"] = url.hostname
        bean["server_port"] = url.port if url.port else 443
        bean["uuid"] = url.username
        bean["flow"] = query.get("flow", [""])[0]

        net = query.get("type", ["tcp"])[0]
        bean["transport"]["type"] = net
        if net == "ws":
            bean["transport"]["path"] = query.get("path", [""])[0]
            bean["transport"]["headers"]["Host"] = query.get("host", [""])[0]
        elif net == "grpc":
            bean["transport"]["service_name"] = query.get("serviceName", [""])[0]

        security = query.get("security", [""])[0]
        if security in ["tls", "reality"]:
            bean["tls"]["enabled"] = True
            bean["tls"]["server_name"] = query.get("sni", [""])[0]
            bean["tls"]["insecure"] = query.get("allowInsecure", ["0"])[0] == "1"
            if "alpn" in query:
                alpn_str = query.get("alpn", [""])[0]
                bean["tls"]["alpn"] = [a.strip() for a in alpn_str.split(',') if a.strip()]

        if security == "reality":
            bean["tls"]["reality"]["enabled"] = True
            bean["tls"]["reality"]["public_key"] = query.get("pbk", [""])[0]
            bean["tls"]["reality"]["short_id"] = query.get("sid", [""])[0]

        return bean
    except (ValueError, IndexError, AttributeError) as e:
        return None


def parse_trojan(link):
    try:
        url = urlparse(link)
        query = parse_qs(url.query)

        bean = get_trojan_template()
        bean["tag"] = unquote(url.fragment) if url.fragment else ""
        bean["server"] = url.hostname
        bean["server_port"] = url.port if url.port else 443
        bean["password"] = unquote(url.username) if url.username else ""

        net = query.get("type", ["tcp"])[0]
        bean["transport"]["type"] = net
        if net == "ws":
            bean["transport"]["path"] = query.get("path", [""])[0]
            bean["transport"]["headers"]["Host"] = query.get("host", [""])[0]

        if query.get("security", [""])[0] == "tls" or not query.get("security"):
            bean["tls"]["enabled"] = True
            bean["tls"]["server_name"] = query.get("sni", [""])[0]
            bean["tls"]["insecure"] = query.get("allowInsecure", ["0"])[0] == "1"
            if "alpn" in query:
                alpn_str = query.get("alpn", [""])[0]
                bean["tls"]["alpn"] = [a.strip() for a in alpn_str.split(',') if a.strip()]

        return bean
    except (ValueError, IndexError, AttributeError) as e:
        return None


def parse_shadowsocks(link):
    try:
        url = urlparse(link)
        bean = get_shadowsocks_template()
        bean["tag"] = unquote(url.fragment) if url.fragment else ""
        bean["server"] = url.hostname
        bean["server_port"] = url.port if url.port else 8388

        if url.password:
            bean["method"] = unquote(url.username) if url.username else ""
            bean["password"] = unquote(url.password)
        else:
            user_info = decode_b64_if_valid(unquote(url.username)) if url.username else ""
            if not user_info:
                return None
            if ':' in user_info:
                bean["method"], bean["password"] = user_info.split(":", 1)
            else:
                return None

        return bean
    except (ValueError, TypeError, AttributeError) as e:
        return None


def parse_hysteria2(link):
    try:
        link = link.replace("hysteria2://", "hy2://")
        url = urlparse(link)
        query = parse_qs(url.query)

        bean = get_hysteria2_template()
        bean["tag"] = unquote(url.fragment) if url.fragment else ""
        bean["server"] = url.hostname
        bean["server_port"] = url.port if url.port else 443
        bean["password"] = unquote(url.username) if url.username else ""

        bean["tls"]["enabled"] = True
        bean["tls"]["insecure"] = query.get("insecure", ["0"])[0] == "1"
        bean["tls"]["server_name"] = query.get("sni", [""])[0]

        if "obfs" in query:
            bean["obfs"]["type"] = query.get("obfs", [""])[0]
            bean["obfs"]["password"] = query.get("obfs-password", [""])[0]

        return bean
    except (ValueError, IndexError, AttributeError) as e:
        return None


def parse_tuic(link):
    try:
        url = urlparse(link)
        query = parse_qs(url.query)

        bean = get_tuic_template()
        bean["tag"] = unquote(url.fragment) if url.fragment else ""
        bean["server"] = url.hostname
        bean["server_port"] = url.port if url.port else 443
        bean["uuid"] = unquote(url.username) if url.username else ""
        bean["password"] = unquote(url.password) if url.password else ""

        bean["congestion_control"] = query.get("congestion_control", ["bbr"])[0]
        bean["udp_relay_mode"] = query.get("udp_relay_mode", ["native"])[0]

        bean["tls"]["enabled"] = True
        bean["tls"]["server_name"] = query.get("sni", [""])[0]
        bean["tls"]["insecure"] = query.get("allow_insecure", ["0"])[0] == "1"
        if "alpn" in query:
            alpn_str = query.get("alpn", [""])[0]
            bean["tls"]["alpn"] = [a.strip() for a in alpn_str.split(',') if a.strip()]

        return bean
    except (ValueError, IndexError, AttributeError) as e:
        return None



def main():
    print("=== ConfigCollector Started (Improved Version) ===")
    sub_content = read_file_text(os.path.join("data", "Sub.txt"))
    if not sub_content:
        print("Error: Sub.txt is empty or not found!")
        return

    sub_links = [link for link in sub_content.splitlines() if link.strip() and not link.startswith("#")]
    print(f"Found {len(sub_links)} subscription links\n")

    unique_configs = OrderedDict()
    subscription_stats = []
    total_downloaded = 0
    total_parsed = 0

    for i, link in enumerate(sub_links):
        print(f"[{i + 1}/{len(sub_links)}] Processing: {link}")
        stats = SubStats(link)
        response = http_get(link)

        if response['error']:
            print(f"  ✗ Error downloading: {response['error']}\n")
            subscription_stats.append(stats)
            continue

        raw_content = response['data'].decode('utf-8', errors='ignore')
        total_downloaded += len(response['data'])
        print(f"  ✓ Downloaded {len(response['data']):,} bytes")

        source_filename = sanitize_filename(link)
        write_file_text(os.path.join("data", "sources", f"{source_filename}.txt"), raw_content)

        beans, line_count, processed_content = parse_subscription(raw_content)
        total_parsed += len(beans)
        print(f"  ✓ Parsed {len(beans)} configs from {line_count} lines")
        stats.total_configs, stats.line_count = len(beans), line_count

        if raw_content != processed_content:
            write_file_text(os.path.join("data", "sources", f"{source_filename}_decoded.txt"), processed_content)

        for bean in beans:
            if not bean or not bean.get('server') or not bean.get('server_port'):
                continue
            key = generate_config_key(bean)
            if key in unique_configs:
                stats.duplicates += 1
            else:
                unique_configs[key] = bean
                stats.unique_configs += 1

        print(f"  ➤ Unique: {stats.unique_configs} | Duplicates: {stats.duplicates}")
        subscription_stats.append(stats)
        print()

    print("\n" + "=" * 60)
    print("=== Saving Unique Configs ===")
    print("=" * 60)

    protocol_counters = {}
    for bean in unique_configs.values():
        proto = bean['type']
        if proto not in protocol_counters:
            protocol_counters[proto] = 0
            os.makedirs(os.path.join("data", "config", proto), exist_ok=True)

        protocol_counters[proto] += 1
        bean["tag"] = f"{proto}-{protocol_counters[proto]}"

        filename = os.path.join("data", "config", proto, f"config_{protocol_counters[proto]:04d}.json")
        write_file_text(filename, json.dumps(bean, indent=2))

    print(f"\n✓ Total unique configs saved: {len(unique_configs)}")
    print(f"\nBreakdown by protocol:")
    for proto, count in sorted(protocol_counters.items()):
        print(f"  • {proto}: {count}")

    print("\n" + "=" * 60)
    print("=== Statistics Summary ===")
    print("=" * 60)
    print(f"Total data downloaded: {total_downloaded:,} bytes ({total_downloaded / 1024 / 1024:.2f} MB)")
    print(f"Total configs parsed: {total_parsed}")
    print(f"Unique configs: {len(unique_configs)}")
    print(f"Duplicate configs removed: {total_parsed - len(unique_configs)}")
    print(f"Deduplication rate: {((total_parsed - len(unique_configs)) / total_parsed * 100):.1f}%")

    print("\n=== ConfigCollector Finished ===")


if __name__ == "__main__":
    main()
