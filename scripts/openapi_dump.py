# FILE: scripts/openapi_dump.py
# Usage: uvicorn tcd.service_http:create_app & then curl http://127.0.0.1:8010/openapi.json
import json, sys, urllib.request
url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8010/openapi.json"
print(json.dumps(json.load(urllib.request.urlopen(url)), indent=2))
