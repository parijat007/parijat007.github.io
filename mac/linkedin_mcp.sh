#!/bin/zsh
# Started by the Claude desktop app: the LinkedIn MCP server (digest/linkedin_mcp.py) with Keychain secrets.
# stdout is the protocol channel, so everything else goes to stderr.
cd "${0:A:h:h}"
WF_MODULE=digest.linkedin_mcp exec /bin/zsh mac/linkedin.sh 2>>/tmp/watchfloor.linkedin-mcp.log
