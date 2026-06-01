import urllib.request
import json

token = "sift_svc_b5152580b0cd2ce8003ee5c9a5c559537b322741f21d4f03"
req1 = urllib.request.Request(
    "https://192.168.122.81:4508/mcp",
    data=json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    }).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
)

ctx = urllib.request.ssl.SSLContext(urllib.request.ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = urllib.request.ssl.CERT_NONE

with urllib.request.urlopen(req1, context=ctx) as response:
    session_id = response.headers.get("mcp-session-id")

req2 = urllib.request.Request(
    "https://192.168.122.81:4508/mcp",
    data=json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "mcp-session-id": session_id
    }
)

with urllib.request.urlopen(req2, context=ctx) as response:
    data = json.loads(response.read().decode('utf-8'))
    for tool in data.get("result", {}).get("tools", []):
        if tool.get("name") == "record_finding":
            print(json.dumps(tool, indent=2))
