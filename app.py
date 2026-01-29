#!/usr/bin/env python3
"""
CerberusEye v5.1 - Universal AI Infrastructure Scanner
XORD LLC Privacy Tools

Double-click to run. Browser opens automatically.
"""

from flask import Flask, render_template, request, jsonify
import threading
import queue
import configparser
import os
import sys
import ssl
import re
import json
import webbrowser
from threading import Timer
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# Global state
scan_results = []
scan_status = {"running": False, "progress": 0, "total": 0, "message": "Idle"}
result_queue = queue.Queue()
manual_targets = []

# SSL context for self-signed certs
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

PLATFORMS = {
    "ollama": {
        "name": "Ollama",
        "icon": "🦙",
        "default_ports": [11434],
        "signatures": {
            "banner": ["Ollama", "ollama"],
            "headers": ["X-Ollama-Version"],
            "endpoints": ["/api/tags", "/api/version"]
        },
        "probe_endpoints": {
            "version": {"path": "/api/version", "desc": "Server version info"},
            "tags": {"path": "/api/tags", "desc": "Available models list"},
            "ps": {"path": "/api/ps", "desc": "Running models"},
            "show": {"path": "/api/show", "desc": "Model details"},
        },
        "shodan_dorks": ['port:11434 "Ollama"'],
        "leakix_query": 'port:11434 "Ollama"',
    },
    
    "open_webui": {
        "name": "Open WebUI",
        "icon": "🌐",
        "default_ports": [3000, 8080],
        "signatures": {
            "html_title": ["Open WebUI", "open-webui"],
            "headers": [],
            "endpoints": ["/api/config", "/health"]
        },
        "probe_endpoints": {
            "config": {"path": "/api/config", "desc": "System configuration"},
            "health": {"path": "/health", "desc": "Health check"},
            "models": {"path": "/api/models", "desc": "Available models"},
            "auth": {"path": "/api/v1/auths", "desc": "Authentication settings"},
            "users": {"path": "/api/v1/users", "desc": "User list (admin)"},
            "chats": {"path": "/api/v1/chats", "desc": "Chat history"},
        },
        "shodan_dorks": ['http.title:"Open WebUI"'],
        "leakix_query": 'http.title:"Open WebUI"',
    },
    
    "localai": {
        "name": "LocalAI",
        "icon": "🤖",
        "default_ports": [8080],
        "signatures": {
            "banner": ["LocalAI"],
            "headers": ["X-LocalAI-Version"],
            "endpoints": ["/v1/models", "/readyz"]
        },
        "probe_endpoints": {
            "models": {"path": "/v1/models", "desc": "Available models (OpenAI compat)"},
            "health": {"path": "/readyz", "desc": "Readiness check"},
            "completions": {"path": "/v1/completions", "desc": "Text completion API"},
            "chat": {"path": "/v1/chat/completions", "desc": "Chat API"},
            "embeddings": {"path": "/v1/embeddings", "desc": "Embedding API"},
        },
        "shodan_dorks": ['"LocalAI" port:8080'],
        "leakix_query": '"LocalAI"',
    },
    
    "vllm": {
        "name": "vLLM",
        "icon": "⚡",
        "default_ports": [8000],
        "signatures": {
            "banner": ["vLLM", "vllm"],
            "headers": [],
            "endpoints": ["/v1/models", "/health"]
        },
        "probe_endpoints": {
            "models": {"path": "/v1/models", "desc": "Loaded models"},
            "health": {"path": "/health", "desc": "Server health"},
            "completions": {"path": "/v1/completions", "desc": "Completion endpoint"},
            "chat": {"path": "/v1/chat/completions", "desc": "Chat endpoint"},
        },
        "shodan_dorks": ['"vllm" port:8000'],
        "leakix_query": '"vLLM"',
    },
    
    "text_gen_webui": {
        "name": "Text Generation WebUI",
        "icon": "📝",
        "default_ports": [7860, 5000],
        "signatures": {
            "html_title": ["Text generation", "oobabooga"],
            "headers": [],
            "endpoints": ["/api/v1/model", "/api/v1/generate"]
        },
        "probe_endpoints": {
            "model": {"path": "/api/v1/model", "desc": "Current model info"},
            "generate": {"path": "/api/v1/generate", "desc": "Text generation API"},
            "chat": {"path": "/api/v1/chat", "desc": "Chat API"},
            "stop": {"path": "/api/v1/stop-stream", "desc": "Stream control"},
        },
        "shodan_dorks": ['http.title:"Text generation"'],
        "leakix_query": 'http.title:"Text generation"',
    },
    
    "lm_studio": {
        "name": "LM Studio",
        "icon": "🎬",
        "default_ports": [1234],
        "signatures": {
            "banner": ["LM Studio"],
            "headers": [],
            "endpoints": ["/v1/models", "/v1/chat/completions"]
        },
        "probe_endpoints": {
            "models": {"path": "/v1/models", "desc": "Available models"},
            "chat": {"path": "/v1/chat/completions", "desc": "Chat API"},
            "completions": {"path": "/v1/completions", "desc": "Completion API"},
        },
        "shodan_dorks": ['"LM Studio" port:1234'],
        "leakix_query": '"LM Studio"',
    },
    
    "moltbot": {
        "name": "Moltbot/ClawdBot",
        "icon": "🦀",
        "default_ports": [443, 3000],
        "signatures": {
            "html_title": ["Clawdbot Control", "Moltbot Control", "clawdbot-control"],
            "headers": ["X-Clawdbot-Version", "X-Moltbot-Version"],
            "endpoints": ["/api/config", "/api/agents"]
        },
        "probe_endpoints": {
            "config": {"path": "/api/config", "desc": "System configuration - API keys, DB URLs"},
            "history": {"path": "/api/history", "desc": "Chat logs - private conversations"},
            "agents": {"path": "/api/agents", "desc": "AI personas - system prompts"},
            "env": {"path": "/api/env", "desc": "Environment variables - SECRETS"},
            "keys": {"path": "/api/keys", "desc": "API key storage"},
            "settings": {"path": "/api/settings", "desc": "User preferences"},
            "health": {"path": "/health", "desc": "Health check"},
        },
        "shodan_dorks": ['http.title:"Clawdbot Control"', 'http.title:"Moltbot Control"'],
        "leakix_query": 'http.title:"Clawdbot Control"',
    },
    
    "openai_compat": {
        "name": "OpenAI-Compatible API",
        "icon": "🔌",
        "default_ports": [8000, 8080, 5000, 3000],
        "signatures": {
            "endpoints": ["/v1/models", "/v1/chat/completions"]
        },
        "probe_endpoints": {
            "models": {"path": "/v1/models", "desc": "Model list (OpenAI format)"},
            "chat": {"path": "/v1/chat/completions", "desc": "Chat completions"},
            "completions": {"path": "/v1/completions", "desc": "Text completions"},
            "embeddings": {"path": "/v1/embeddings", "desc": "Embeddings API"},
        },
        "shodan_dorks": ['"/v1/models" port:8000,8080'],
        "leakix_query": '"/v1/models"',
    },
}

# Credential patterns for deep scan
CREDENTIAL_PATTERNS = {
    "Anthropic API Key": r"sk-ant-[a-zA-Z0-9-_]{20,}",
    "OpenAI API Key": r"sk-[a-zA-Z0-9]{32,}",
    "Telegram Bot Token": r"\d{8,10}:[A-Za-z0-9_-]{35}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]+",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Discord Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "HuggingFace Token": r"hf_[a-zA-Z0-9]{34}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Generic API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9-_]{20,})",
    "Generic Secret": r"secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9-_]{20,})",
    "Password Field": r"password['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})",
    "Private Key": r"-----BEGIN (RSA |EC |)PRIVATE KEY-----",
}


def load_config():
    """Load API keys from config.ini"""
    config = configparser.ConfigParser()
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(__file__)
    config_path = os.path.join(base_path, "config.ini")
    
    if os.path.exists(config_path):
        config.read(config_path)
    
    return {
        "leakix": config.get("leakix", "api_key", fallback=""),
        "censys": config.get("censys", "api_key", fallback=""),
        "shodan": config.get("shodan", "api_key", fallback="")
    }


def save_config(keys):
    """Save API keys to config.ini"""
    config = configparser.ConfigParser()
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(__file__)
    config_path = os.path.join(base_path, "config.ini")
    
    config["leakix"] = {"api_key": keys.get("leakix", "")}
    config["censys"] = {"api_key": keys.get("censys", "")}
    config["shodan"] = {"api_key": keys.get("shodan", "")}
    
    with open(config_path, "w") as f:
        config.write(f)


# ═══════════════════════════════════════════════════════════════════════════════
# INTEL GATHERING
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_leakix(api_key, query):
    """Query LeakIX"""
    try:
        import requests
    except ImportError:
        return [], "requests not installed"
    
    headers = {"Accept": "application/json"}
    if api_key:
        headers["api-key"] = api_key
    
    try:
        res = requests.get(
            "https://leakix.net/search",
            params={"q": query, "scope": "service"},
            headers=headers,
            timeout=15
        )
        
        if res.status_code == 200:
            data = res.json()
            targets = []
            if isinstance(data, list):
                for item in data:
                    ip = item.get("ip")
                    port = item.get("port", 80)
                    if ip:
                        targets.append({"host": f"{ip}:{port}", "source": "LeakIX"})
            return targets, f"Found {len(targets)}"
        else:
            return [], f"Error: {res.status_code}"
    except Exception as e:
        return [], str(e)[:50]


def fetch_shodan(api_key, query):
    """Query Shodan"""
    if not api_key:
        return [], "No API key"
    
    try:
        import requests
    except ImportError:
        return [], "requests not installed"
    
    try:
        res = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": api_key, "query": query, "minify": "true"},
            timeout=15
        )
        
        if res.status_code == 200:
            data = res.json()
            targets = []
            for match in data.get("matches", []):
                ip = match.get("ip_str")
                port = match.get("port", 80)
                if ip:
                    targets.append({"host": f"{ip}:{port}", "source": "Shodan"})
            return targets, f"Found {len(targets)}"
        else:
            return [], f"Error: {res.status_code}"
    except Exception as e:
        return [], str(e)[:50]


def fetch_censys(api_key, query):
    """Query Censys"""
    if not api_key:
        return [], "No API key"
    
    try:
        import requests
    except ImportError:
        return [], "requests not installed"
    
    try:
        res = requests.post(
            "https://api.platform.censys.io/v3/global/search/query",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={"query": query},
            timeout=15
        )
        
        if res.status_code == 200:
            data = res.json()
            hits = data.get("result", {}).get("hits", [])
            targets = []
            for hit in hits:
                ip = hit.get("ip")
                if ip:
                    targets.append({"host": f"{ip}:443", "source": "Censys"})
            return targets, f"Found {len(targets)}"
        else:
            return [], f"Error: {res.status_code}"
    except Exception as e:
        return [], str(e)[:50]


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_url(url, timeout=5):
    """Fetch URL with timeout"""
    try:
        req = Request(url, headers={
            "User-Agent": "CerberusEye/5.1 (XORD LLC Security Audit)",
            "Accept": "application/json, text/html, */*"
        })
        response = urlopen(req, timeout=timeout, context=ssl_context)
        content = response.read().decode('utf-8', errors='ignore')
        headers = dict(response.headers)
        return content, headers, response.status
    except HTTPError as e:
        return None, None, e.code
    except:
        return None, None, 0


def identify_platform(host):
    """Identify which AI platform is running on a host"""
    for protocol in ["https", "http"]:
        base_url = f"{protocol}://{host}"
        content, headers, status = fetch_url(base_url, timeout=3)
        
        if status == 0:
            continue
        
        detected = []
        
        for platform_id, platform in PLATFORMS.items():
            confidence = 0
            
            if content and "html_title" in platform.get("signatures", {}):
                for title in platform["signatures"]["html_title"]:
                    if title.lower() in content.lower():
                        confidence += 50
                        break
            
            if headers and "headers" in platform.get("signatures", {}):
                for header in platform["signatures"]["headers"]:
                    if header in headers:
                        confidence += 40
                        break
            
            if content and "banner" in platform.get("signatures", {}):
                for banner in platform["signatures"]["banner"]:
                    if banner.lower() in content.lower():
                        confidence += 30
                        break
            
            if "endpoints" in platform.get("signatures", {}):
                for endpoint in platform["signatures"]["endpoints"]:
                    _, _, ep_status = fetch_url(f"{base_url}{endpoint}", timeout=3)
                    if ep_status == 200:
                        confidence += 25
                        break
            
            if confidence > 0:
                detected.append({
                    "platform": platform_id,
                    "name": platform["name"],
                    "icon": platform["icon"],
                    "confidence": min(confidence, 100),
                    "protocol": protocol
                })
        
        if detected:
            detected.sort(key=lambda x: x["confidence"], reverse=True)
            return detected[0], base_url
    
    return None, None


def scan_target(host):
    """Scan a single target with false-positive detection"""
    platform_info, base_url = identify_platform(host)
    
    if not platform_info:
        return None
    
    result = {
        "host": host,
        "url": base_url,
        "platform": platform_info["platform"],
        "platform_name": platform_info["name"],
        "platform_icon": platform_info["icon"],
        "confidence": platform_info["confidence"],
        "timestamp": datetime.now().isoformat(),
        "risk_level": "LOW",
        "findings": [],
        "likely_false_positive": False
    }
    
    platform = PLATFORMS[platform_info["platform"]]
    
    response_sizes = []
    accessible_endpoints = []
    has_json_response = False
    has_real_data = False
    
    for name, info in list(platform["probe_endpoints"].items())[:4]:
        content, headers, status = fetch_url(f"{base_url}{info['path']}", timeout=3)
        
        if status == 200 and content:
            response_sizes.append(len(content))
            accessible_endpoints.append(info['path'])
            
            content_lower = content[:500].lower()
            if content.strip().startswith('{') or content.strip().startswith('['):
                has_json_response = True
                if any(k in content_lower for k in ['"models"', '"name"', '"version"', '"id"', 'sk-', 'api_key', '"data"']):
                    has_real_data = True
            
            if '<!doctype' in content_lower or '<html' in content_lower:
                if any(fp in content_lower for fp in ['vercel', 'next', 'nginx', 'apache', 'welcome to']):
                    result["likely_false_positive"] = True
    
    if len(response_sizes) >= 2:
        if len(set(response_sizes)) == 1:
            result["likely_false_positive"] = True
    
    if accessible_endpoints:
        result["findings"] = [f"{ep} accessible" for ep in accessible_endpoints]
        
        if result["likely_false_positive"]:
            result["risk_level"] = "LOW"
            result["findings"].append("⚠️ Likely false positive")
        elif has_real_data:
            result["risk_level"] = "CRITICAL"
        elif has_json_response:
            result["risk_level"] = "HIGH"
        else:
            result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "LOW"
    
    return result


def run_scan(selected_platforms):
    """Main scan function"""
    global scan_results, scan_status, manual_targets
    
    scan_results = []
    scan_status = {"running": True, "progress": 0, "total": 0, "message": "Initializing..."}
    
    keys = load_config()
    all_targets = []
    
    if manual_targets:
        for t in manual_targets:
            all_targets.append({"host": t, "source": "Manual"})
        result_queue.put({"type": "intel", "source": "Manual", "count": len(manual_targets), "message": f"{len(manual_targets)} targets"})
    
    for platform_id in selected_platforms:
        if platform_id not in PLATFORMS:
            continue
        
        platform = PLATFORMS[platform_id]
        scan_status["message"] = f"Querying for {platform['name']}..."
        
        if platform.get("leakix_query"):
            targets, msg = fetch_leakix(keys["leakix"], platform["leakix_query"])
            if targets:
                all_targets.extend(targets)
                result_queue.put({"type": "intel", "source": f"LeakIX ({platform['name']})", "count": len(targets), "message": msg})
        
        if platform.get("shodan_dorks") and keys["shodan"]:
            targets, msg = fetch_shodan(keys["shodan"], platform["shodan_dorks"][0])
            if targets:
                all_targets.extend(targets)
                result_queue.put({"type": "intel", "source": f"Shodan ({platform['name']})", "count": len(targets), "message": msg})
    
    seen = set()
    unique_targets = []
    for t in all_targets:
        if t["host"] not in seen:
            seen.add(t["host"])
            unique_targets.append(t)
    
    scan_status["total"] = len(unique_targets)
    scan_status["message"] = f"Scanning {len(unique_targets)} targets..."
    
    scanned = 0
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_target, t["host"]): t for t in unique_targets}
        
        for future in as_completed(futures):
            scanned += 1
            scan_status["progress"] = scanned
            
            try:
                result = future.result()
                if result:
                    scan_results.append(result)
                    result_queue.put({"type": "finding", "data": result})
            except:
                pass
    
    scan_status["running"] = False
    scan_status["message"] = f"Complete. Found {len(scan_results)} exposed instances."
    result_queue.put({"type": "complete", "total": len(scan_results)})


# ═══════════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/platforms")
def get_platforms():
    result = {}
    for pid, p in PLATFORMS.items():
        result[pid] = {
            "name": p["name"],
            "icon": p["icon"],
            "ports": p["default_ports"],
            "dorks": p.get("shodan_dorks", [])
        }
    return jsonify(result)


@app.route("/api/config", methods=["GET", "POST"])
def handle_config():
    if request.method == "GET":
        keys = load_config()
        return jsonify({
            "leakix": "***" if keys["leakix"] else "",
            "censys": "***" if keys["censys"] else "",
            "shodan": "***" if keys["shodan"] else ""
        })
    else:
        data = request.json
        save_config(data)
        return jsonify({"status": "saved"})


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    global manual_targets
    
    if scan_status["running"]:
        return jsonify({"error": "Scan already running"}), 400
    
    data = request.json or {}
    selected = data.get("platforms", list(PLATFORMS.keys()))
    
    thread = threading.Thread(target=run_scan, args=(selected,), daemon=True)
    thread.start()
    
    return jsonify({"status": "started"})


@app.route("/api/scan/status")
def get_status():
    results = []
    while not result_queue.empty():
        try:
            results.append(result_queue.get_nowait())
        except:
            break
    
    return jsonify({
        "status": scan_status,
        "updates": results
    })


@app.route("/api/targets/manual", methods=["POST"])
def add_manual_targets():
    global manual_targets
    
    data = request.json
    raw = data.get("targets", "")
    
    lines = re.split(r"[,\n\r]+", raw)
    parsed = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            line = f"{line}:11434"
        parsed.append(line)
    
    manual_targets = list(set(parsed))
    return jsonify({"status": "ok", "count": len(manual_targets)})


@app.route("/api/deep-scan", methods=["POST"])
def deep_scan():
    data = request.json
    target_url = data.get("url", "")
    platform_id = data.get("platform", "openai_compat")
    
    if not target_url:
        return jsonify({"error": "No URL"}), 400
    
    platform = PLATFORMS.get(platform_id, PLATFORMS["openai_compat"])
    
    results = {
        "target": target_url,
        "platform": platform["name"],
        "platform_icon": platform["icon"],
        "timestamp": datetime.now().isoformat(),
        "endpoints": {},
        "exposed_credentials": [],
        "exposed_models": [],
        "risk_level": "UNKNOWN",
        "findings": [],
        "verdict": ""
    }
    
    base_url = target_url.rstrip("/")
    response_sizes = []
    accessible_count = 0
    
    for name, info in platform["probe_endpoints"].items():
        url = base_url + info["path"]
        
        try:
            content, headers, status = fetch_url(url, timeout=10)
            
            if status == 200 and content:
                preview = (content[:500] + '...') if len(content) > 500 else content
                response_sizes.append(len(content))
                accessible_count += 1
                
                results["endpoints"][name] = {
                    "url": url,
                    "path": info["path"],
                    "status": status,
                    "size": len(content),
                    "accessible": True,
                    "desc": info["desc"],
                    "preview": preview,
                    "server": headers.get("Server", "Unknown") if headers else "Unknown"
                }
                
                for cred_name, pattern in CREDENTIAL_PATTERNS.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if len(match) > 8:
                            redacted = match[:6] + "..." + match[-4:]
                            finding = {"type": cred_name, "value": redacted, "endpoint": name}
                            if finding not in results["exposed_credentials"]:
                                results["exposed_credentials"].append(finding)
                                results["findings"].append(f"🔑 {cred_name} in {info['path']}")
                
                if name in ["models", "tags"]:
                    try:
                        model_data = json.loads(content)
                        models = model_data.get("models", model_data.get("data", []))
                        if models:
                            for m in models[:10]:
                                model_name = m.get("name", m.get("id", str(m)))
                                results["exposed_models"].append(model_name)
                            results["findings"].append(f"📦 {len(models)} models exposed")
                    except:
                        pass
            else:
                results["endpoints"][name] = {
                    "url": url,
                    "path": info["path"],
                    "status": status,
                    "accessible": False,
                    "desc": info["desc"]
                }
        except Exception as e:
            results["endpoints"][name] = {
                "url": url,
                "path": info["path"],
                "status": 0,
                "accessible": False,
                "error": str(e)[:50],
                "desc": info["desc"]
            }
    
    cred_count = len(results["exposed_credentials"])
    all_same_size = len(set(response_sizes)) == 1 and len(response_sizes) > 2
    
    if all_same_size:
        results["verdict"] = "⚠️ LIKELY FALSE POSITIVE: All endpoints return identical size responses. Probably a default page."
        results["risk_level"] = "LOW"
    elif cred_count > 0:
        results["risk_level"] = "CRITICAL"
        results["verdict"] = f"🚨 CREDENTIALS EXPOSED: {cred_count} secrets found in responses!"
    elif accessible_count >= 3:
        results["risk_level"] = "HIGH"
        results["verdict"] = "⚠️ Multiple API endpoints accessible without authentication."
    elif accessible_count >= 1:
        results["risk_level"] = "MEDIUM"
        results["verdict"] = "Some endpoints accessible. Check if authentication is required."
    else:
        results["risk_level"] = "LOW"
        results["verdict"] = "No accessible endpoints found."
    
    return jsonify(results)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN - Auto-opens browser
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*70)
    print("  CERBERUSEYE v5.1 - Universal AI Infrastructure Scanner")
    print("  XORD LLC")
    print("="*70)
    print("\n  Browser will open automatically...")
    print("  Close this window to stop the server.\n")
    
    # Auto-open browser after 1.5 seconds
    Timer(1.5, lambda: webbrowser.open("http://localhost:5000")).start()
    
    app.run(debug=False, port=5000, threaded=True)
