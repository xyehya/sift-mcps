#!/usr/bin/env python3
"""
Run this once on Fedora (in the same directory as the exported index.html)
to create index-standalone.html — the server-compatible version.

Usage:
    python3 patch.py
"""

import sys
import os

src = os.path.join(os.path.dirname(__file__), "index.html")
dst = os.path.join(os.path.dirname(__file__), "index-standalone.html")

if not os.path.exists(src):
    print(f"ERROR: {src} not found. Copy the artifact HTML here first.")
    sys.exit(1)

with open(src, "r", encoding="utf-8") as f:
    html = f.read()

# 1. Update repo path
old_repo = 'const REPO = "/Users/yk/Fedora/SIFTHACK/sift-mcps"'
new_repo = 'const REPO = "/home/yk/AI/SIFTHACK/sift-mcps"'

if old_repo not in html:
    print("WARNING: REPO line not found — already patched, or HTML changed.")
else:
    html = html.replace(old_repo, new_repo)
    print("✓ Updated REPO path")

# 2. Replace window.cowork.callMcpTool with local fetch calls
old_mcp = (
    'async function mcp(name,args){\n'
    '  if(!window.cowork||typeof window.cowork.callMcpTool!=="function") throw new Error("window.cowork.callMcpTool unavailable");\n'
    '  const r=await window.cowork.callMcpTool(name,args);\n'
    '  if(r&&r.isError){ let d=""; try{d=(r.content&&r.content[0]&&r.content[0].text)?r.content[0].text:JSON.stringify(r);}catch(e){} throw new Error("isError :: "+String(d).slice(0,200)); }\n'
    '  let p=(r&&r.structuredContent!=null)?r.structuredContent:null;\n'
    '  if(p==null&&r&&r.content&&r.content[0]&&r.content[0].text!=null){ const t=r.content[0].text; try{p=JSON.parse(t);}catch(e){p=t;} }\n'
    '  return p;\n'
    '}'
)
new_mcp = (
    'async function mcp(name,args){\n'
    '  if(/write/i.test(name)){\n'
    '    const r=await fetch(\'/api/write\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({path:args.path,content:args.content})});\n'
    '    if(!r.ok) throw new Error(await r.text());\n'
    '    return \'ok\';\n'
    '  }\n'
    '  const r=await fetch(\'/api/read?path=\'+encodeURIComponent(args.path));\n'
    '  if(!r.ok) throw new Error(await r.text());\n'
    '  return await r.text();\n'
    '}'
)

if old_mcp not in html:
    print("WARNING: mcp() function not found verbatim — may have changed. Check index-standalone.html manually.")
else:
    html = html.replace(old_mcp, new_mcp)
    print("✓ Replaced mcp() to use local fetch instead of window.cowork")

with open(dst, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\nWrote: {dst}")
print("Next: python3 server.py  →  open http://localhost:8787")
