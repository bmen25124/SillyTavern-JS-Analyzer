A server plugin for [SillyTavern](https://docs.sillytavern.app/). It makes a idiomatic analysis of JavaScript code to detect potentially dangerous operations, such as network requests, eval calls, and other unsafe APIs. It can also sanitize the code by removing or commenting out dangerous parts.

This is not a full-fledged JavaScript interpreter like [SandboxJS](https://github.com/nyariv/SandboxJS). It uses [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to parse JavaScript code and analyze its structure. If you have a more complex use case, use something else.


## Installation

1. Open a terminal in `{SillyTavern_Folder}/plugins`.
```bash
git clone https://github.com/bmen25124/SillyTavern-JS-Analyzer
```

2. Set `enableServerPlugins: true` in `{SillyTavern_Folder}/config.yaml`.
3. Restart the server.

## Usage

Example request: `POST /api/plugins/js-security/analyze`
```json
{
    "code": "showPage_67('drawings'); fetch('https://www.google.com/');",
    "settings": {
        "allowedAPIs": [
            "console",
            "Math",
            "Date",
            "JSON",
            "parseInt",
            "parseFloat",
            "isNaN",
            "isFinite"
        ],
        "blockedAPIs": [
            "fetch",
            "XMLHttpRequest",
            "eval",
            "Function",
            "WebSocket",
            "localStorage",
            "sessionStorage"
        ],
        "maxScriptLength": 50000,
        "allowObfuscation": false
    }
}
```

Response:
```json
{
    "safe": false,
    "violations": [
        {
            "type": "dangerous_api_call",
            "node": "fetch",
            "position": {
                "row": 0,
                "column": 25
            },
            "severity": "error",
            "message": "Blocked dangerous API call: fetch"
        }
    ],
    "sanitizedCode": "showPage_67('drawings'); /* fetch() blocked for security */('https://www.google.com/');"
}
```
