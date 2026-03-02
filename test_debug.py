import sys
from pathlib import Path
from basalguard.core.agent_firewall import BasalGuardCore

fw = BasalGuardCore(Path("/tmp/ws"))
res = fw.safe_web_request("https://www.example.com/")
print(res)
