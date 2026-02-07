
# Sing Box converter

Powerful proxy subscription parser & converter to Sing-Box JSON format.

## Supported Protocols
- ✅ VMess
- ✅ VLess (with Reality)
- ✅ Trojan  
- ✅ Shadowsocks
- ✅ Hysteria2
- ✅ TUIC


## Quick Start

```bash
# Install dependencies
pip install requests

# Setup
mkdir -p data
echo "https://your-subscription.com" > data/Sub.txt

# Run
python convertor.py
```

## Input Format
`data/Sub.txt` - One subscription URL per line:
```
```

## Output
```
data/
├── sources/          # Raw subscription data
└── config/          # Organized JSON configs
    ├── vmess/
    ├── vless/
    ├── trojan/
    ├── shadowsocks/
    ├── hysteria2/
    └── tuic/
```

## JSON Output Structures

### VMess
```json
{
  "type": "vmess",
  "tag": "",
  "server": "",
  "server_port": 0,
  "uuid": "",
  "security": "auto",
  "alter_id": 0,
  "transport": {
    "type": "",
    "path": "",
    "headers": {},
    "service_name": ""
  },
  "tls": {
    "enabled": false,
    "server_name": "",
    "insecure": false,
    "alpn": []
  }
}
```

### VLess (Reality Support)
```json
{
  "type": "vless",
  "tag": "",
  "server": "",
  "server_port": 0,
  "uuid": "",
  "flow": "",
  "packet_encoding": "xudp",
  "transport": {
    "type": "",
    "path": "",
    "headers": {},
    "service_name": ""
  },
  "tls": {
    "enabled": false,
    "server_name": "",
    "insecure": false,
    "alpn": [],
    "reality": {
      "enabled": false,
      "public_key": "",
      "short_id": ""
    }
  }
}
```

### Trojan
```json
{
  "type": "trojan",
  "tag": "",
  "server": "",
  "server_port": 0,
  "password": "",
  "transport": {
    "type": "",
    "path": "",
    "headers": {}
  },
  "tls": {
    "enabled": false,
    "server_name": "",
    "insecure": false,
    "alpn": []
  }
}
```

### Shadowsocks
```json
{
  "type": "shadowsocks",
  "tag": "",
  "server": "",
  "server_port": 0,
  "method": "",
  "password": ""
}
```

### Hysteria2
```json
{
  "type": "hysteria2",
  "tag": "",
  "server": "",
  "server_port": 0,
  "password": "",
  "obfs": {
    "type": "",
    "password": ""
  },
  "tls": {
    "enabled": false,
    "server_name": "",
    "insecure": false,
    "alpn": []
  }
}
```

### TUIC
```json
{
  "type": "tuic",
  "tag": "",
  "server": "",
  "server_port": 0,
  "uuid": "",
  "password": "",
  "congestion_control": "bbr",
  "udp_relay_mode": "native",
  "zero_rtt_handshake": false,
  "heartbeat": "10s",
  "tls": {
    "enabled": false,
    "server_name": "",
    "insecure": false,
    "alpn": []
  }
}
```


## Features
- Smart Base64 decoding
- Auto protocol detection
- Duplicate removal
- Full statistics
- Supports mislabeled configs
