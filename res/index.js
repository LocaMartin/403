#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const readline = require('readline');
const { spawn } = require('child_process');

// Try to load optional dependencies; if missing, show install message
let axios, chalk, yargs, yaml, HttpsProxyAgent, SocksProxyAgent;
try {
  axios = require('axios');
  chalk = require('chalk');
  yargs = require('yargs/yargs');
  yaml = require('yaml');
  HttpsProxyAgent = require('https-proxy-agent');
  SocksProxyAgent = require('socks-proxy-agent');
} catch (e) {
  console.error('Missing dependencies. Run: npm install axios chalk yargs yaml https-proxy-agent socks-proxy-agent');
  process.exit(1);
}

// ----------------------------------------------------------------------------
// Load configuration from res/config.yaml (required)
// ----------------------------------------------------------------------------
const CONFIG_PATH = path.join(__dirname, 'res', 'config.yaml');
if (!fs.existsSync(CONFIG_PATH)) {
  console.error(chalk.red(`[!] Configuration file not found: ${CONFIG_PATH}`));
  console.error(chalk.red('Please ensure res/config.yaml exists.'));
  process.exit(1);
}

let config;
try {
  const file = fs.readFileSync(CONFIG_PATH, 'utf8');
  config = yaml.parse(file);
} catch (err) {
  console.error(chalk.red(`[!] Failed to parse ${CONFIG_PATH}: ${err.message}`));
  process.exit(1);
}

// Validate required sections (optional but helpful)
const requiredSections = ['path_payloads', 'override_headers', 'ip_bypass_headers', 'ip_values'];
for (const section of requiredSections) {
  if (!config[section]) {
    console.error(chalk.red(`[!] Missing required section "${section}" in ${CONFIG_PATH}`));
    process.exit(1);
  }
}

// ----------------------------------------------------------------------------
// CLI arguments
// ----------------------------------------------------------------------------
const argv = yargs(process.argv.slice(2))
  .usage('$0 [options]')
  .option('t', {
    alias: 'target',
    describe: 'Target URL or file with URLs (one per line)',
    type: 'string'
  })
  .option('x', {
    alias: 'method',
    describe: 'HTTP method (default: GET)',
    type: 'string',
    default: 'GET'
  })
  .option('H', {
    alias: 'header',
    describe: 'Custom headers (can be repeated)',
    type: 'array',
    default: []
  })
  .option('p', {
    alias: 'path-payload',
    describe: 'Custom path payloads (can be repeated)',
    type: 'array',
    default: []
  })
  .option('port', {
    describe: 'Custom port',
    type: 'number'
  })
  .option('proxy', {
    describe: 'Proxy URL (e.g., socks5://127.0.0.1:9050)',
    type: 'string'
  })
  .option('vct', {
    describe: 'View content type',
    type: 'boolean',
    default: false
  })
  .option('vcl', {
    describe: 'View content length',
    type: 'boolean',
    default: false
  })
  .option('up', {
    describe: 'Update 403 tool',
    type: 'boolean',
    default: false
  })
  .option('h', {
    alias: 'help',
    describe: 'Show help',
    type: 'boolean'
  })
  .help(false)
  .version(false)
  .argv;

if (argv.h) {
  console.log(`
Usage: 403 [options]

Options:
  -t, --target <url|file>   Target URL or file with URLs
  -x, --method <method>      HTTP method (default: GET)
  -H, --header <header>       Custom headers (e.g., "X-Forwarded-For: 127.0.0.1")
  -p, --path-payload <path>   Custom path payloads
  --port <port>               Custom port
  --proxy <proxy>              Proxy URL (e.g., socks5://127.0.0.1:9050)
  --vct                        Show content type
  --vcl                        Show content length
  --up                         Update tool
  -h, --help                   Show this help
  `);
  process.exit(0);
}

if (argv.up) {
  console.log(chalk.cyan('Updating 403...'));
  const npm = spawn('npm', ['install', '-g', '403'], { stdio: 'inherit' });
  npm.on('close', (code) => {
    if (code === 0) console.log(chalk.green('Update complete.'));
    else console.log(chalk.red('Update failed.'));
    process.exit(code);
  });
  return;
}

// ----------------------------------------------------------------------------
// Prepare targets list
// ----------------------------------------------------------------------------
let targets = [];
if (argv.t) {
  // Check if it's a file
  if (fs.existsSync(argv.t) && fs.statSync(argv.t).isFile()) {
    targets = fs.readFileSync(argv.t, 'utf8').split('\n').filter(Boolean);
  } else {
    targets = [argv.t];
  }
} else {
  // Read from stdin
  const rl = readline.createInterface({ input: process.stdin });
  targets = await new Promise(resolve => {
    const lines = [];
    rl.on('line', line => lines.push(line));
    rl.on('close', () => resolve(lines.filter(Boolean)));
  });
}

if (targets.length === 0) {
  console.error(chalk.red('No targets provided. Use -t or pipe URLs.'));
  process.exit(1);
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function colorizeStatus(status) {
  if (status >= 200 && status < 300) return chalk.green(status);
  if (status >= 400 && status < 500) return chalk.red(status);
  if (status >= 500) return chalk.yellow(status);
  return chalk.blue(status);
}

function parseHeaders(headerArray) {
  const headers = {};
  for (const h of headerArray) {
    const idx = h.indexOf(':');
    if (idx > 0) {
      const key = h.slice(0, idx).trim();
      const val = h.slice(idx + 1).trim();
      headers[key] = val;
    }
  }
  return headers;
}

function buildRequestConfig(targetUrl, method, customHeaders, proxyUrl, customPort) {
  const url = new URL(targetUrl);
  const configReq = {
    method: method,
    url: targetUrl,
    headers: customHeaders,
    maxRedirects: 0,
    validateStatus: () => true, // accept any status
    httpAgent: null,
    httpsAgent: null
  };

  if (proxyUrl) {
    const ProxyAgent = proxyUrl.startsWith('socks') ? SocksProxyAgent : HttpsProxyAgent;
    const agent = new ProxyAgent(proxyUrl);
    if (url.protocol === 'https:') {
      configReq.httpsAgent = agent;
    } else {
      configReq.httpAgent = agent;
    }
  }

  if (customPort) {
    url.port = customPort;
    configReq.url = url.toString();
  }

  return configReq;
}

// ----------------------------------------------------------------------------
// Test generation (uses config loaded from YAML)
// ----------------------------------------------------------------------------
function generateTests(target, customPathPayloads = []) {
  const baseUrl = new URL(target);
  const originalPath = baseUrl.pathname;
  const tests = [];

  // Helper to add a test
  function addTest(description, url, headers = {}, method = argv.x) {
    tests.push({
      description,
      url,
      headers,
      method
    });
  }

  // 1. Path manipulation (from config + custom)
  const allPathPayloads = [...config.path_payloads, ...customPathPayloads];
  for (const payload of allPathPayloads) {
    let newPath;
    if (payload.startsWith('/') || payload.startsWith('?') || payload.startsWith('#')) {
      // absolute modification
      newPath = originalPath + payload;
    } else {
      // append as extension or suffix
      newPath = originalPath + payload;
    }
    const url = new URL(baseUrl);
    url.pathname = newPath;
    addTest(`Path: ${payload}`, url.toString());
  }

  // 2. Header overrides (X-Original-URL, X-Rewrite-URL) from config
  for (const [header, valueTemplate] of Object.entries(config.override_headers)) {
    const value = valueTemplate.replace('{}', originalPath);
    const headers = { [header]: value };
    const url = new URL(baseUrl);
    url.pathname = '/'; // set root, original path goes in header
    addTest(`Header override: ${header}`, url.toString(), headers);
  }

  // 3. IP spoofing headers from config
  for (const ipHeader of config.ip_bypass_headers) {
    for (const ipValue of config.ip_values) {
      const headers = { [ipHeader]: ipValue };
      addTest(`IP spoof: ${ipHeader}: ${ipValue}`, target, headers);
    }
  }

  // 4. Content-Length manipulation (static tests – can be extended via config later)
  const clTests = [
    { desc: 'Content-Length: 0', headers: { 'Content-Length': '0' } },
    { desc: 'Content-Length: -1', headers: { 'Content-Length': '-1' } },
    { desc: 'Content-Length: 9999999999', headers: { 'Content-Length': '9999999999' } }
  ];
  for (const t of clTests) {
    addTest(`Content-Length: ${t.desc}`, target, t.headers, argv.x);
  }

  // 5. HTTP/0.9 downgrade (placeholder; actual implementation would require raw socket)
  addTest('HTTP/0.9 downgrade', target, {}, argv.x);

  // 6. Race condition: /secret/secret
  const racePath = originalPath + originalPath;
  const raceUrl = new URL(baseUrl);
  raceUrl.pathname = racePath;
  addTest('Race condition (path doubling)', raceUrl.toString());

  // 7. Method override (try common methods)
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD'];
  for (const m of methods) {
    if (m !== argv.x) {
      addTest(`Method override: ${m}`, target, {}, m);
    }
  }

  // 8. Unicode/encoding variations (hardcoded as they are not in config)
  const unicodeTests = [
    { desc: 'Unicode homoglyph (admin → аdmin)', path: originalPath.replace(/a/g, 'а') }, // Cyrillic a
    { desc: 'Case variation', path: originalPath.split('/').map(p => p.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('')).join('/') },
    { desc: 'Double URL encode', path: originalPath.split('/').map(p => encodeURIComponent(encodeURIComponent(p))).join('/') }
  ];
  for (const t of unicodeTests) {
    const url = new URL(baseUrl);
    url.pathname = t.path;
    addTest(t.desc, url.toString());
  }

  return tests;
}

// ----------------------------------------------------------------------------
// Main execution
// ----------------------------------------------------------------------------
(async () => {
  const customHeaders = parseHeaders(argv.H || []);
  const customPathPayloads = argv.p || [];

  // For each target, run tests
  for (const target of targets) {
    console.log(chalk.cyan(`\n[>] Testing: ${target}`));
    const tests = generateTests(target, customPathPayloads);

    for (const test of tests) {
      try {
        const configReq = buildRequestConfig(test.url, test.method, { ...customHeaders, ...test.headers }, argv.proxy, argv.port);
        const response = await axios(configReq);

        const status = response.status;
        const statusColored = colorizeStatus(status);
        const contentType = response.headers['content-type'] || 'N/A';
        const contentLength = response.headers['content-length'] || response.data?.length || 'N/A';

        let output = `  ${statusColored} – ${test.description} [${test.method}] ${test.url}`;
        if (argv.vct) output += ` | Type: ${contentType}`;
        if (argv.vcl) output += ` | Length: ${contentLength}`;
        console.log(output);

      } catch (err) {
        // Network errors, timeouts, etc.
        console.log(chalk.red(`  ERROR – ${test.description} [${test.method}] ${test.url} – ${err.message}`));
      }
    }
  }

  console.log(chalk.green('\n[*] Testing complete.'));
})();