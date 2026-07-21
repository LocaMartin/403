#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { URL } from 'url';
import readline from 'readline';
import { spawn } from 'child_process';
import axios from 'axios';
import chalk from 'chalk';
import yargs from 'yargs/yargs';
import { parse as parseYaml } from 'yaml';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----------------------------------------------------------------------------
// Load configuration from res/config.yaml (required)
// ----------------------------------------------------------------------------
const CONFIG_PATH = path.join(__dirname, 'config.yaml');
if (!fs.existsSync(CONFIG_PATH)) {
  console.error(chalk.red(`[!] Configuration file not found: ${CONFIG_PATH}`));
  console.error(chalk.red('Please ensure res/config.yaml exists.'));
  process.exit(1);
}

let config;
try {
  const file = fs.readFileSync(CONFIG_PATH, 'utf8');
  config = parseYaml(file);
} catch (err) {
  console.error(chalk.red(`[!] Failed to parse ${CONFIG_PATH}: ${err.message}`));
  process.exit(1);
}

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
  .option('t', { alias: 'target', describe: 'Target URL or file with URLs (one per line)', type: 'string' })
  .option('x', { alias: 'method', describe: 'HTTP method (default: GET)', type: 'string', default: 'GET' })
  .option('H', { alias: 'header', describe: 'Custom headers (can be repeated)', type: 'array', default: [] })
  .option('p', { alias: 'path-payload', describe: 'Custom path payloads (can be repeated)', type: 'array', default: [] })
  .option('port', { describe: 'Custom port', type: 'number' })
  .option('proxy', { describe: 'Proxy URL (e.g., socks5://127.0.0.1:9050)', type: 'string' })
  .option('vct', { describe: 'View content type', type: 'boolean', default: false })
  .option('vcl', { describe: 'View content length', type: 'boolean', default: false })
  .option('concurrency', { alias: 'c', describe: 'Concurrent requests per target', type: 'number', default: 15 })
  .option('timeout', { describe: 'Per-request timeout in ms', type: 'number', default: 10000 })
  .option('delay', { describe: 'Base delay before each request, in ms', type: 'number', default: 0 })
  .option('jitter', { describe: 'Random extra delay (0-N ms) added to --delay', type: 'number', default: 0 })
  .option('progress', { describe: 'Show the live progress indicator (use --no-progress to disable)', type: 'boolean', default: true })
  .option('up', { describe: 'Update 403 tool', type: 'boolean', default: false })
  .option('h', { alias: 'help', describe: 'Show help', type: 'boolean' })
  .help(false)
  .version(false)
  .argv;

// ----------------------------------------------------------------------------
// Category colors — used for both the help legend and per-test output
// ----------------------------------------------------------------------------
const categoryColor = {
  path: chalk.blueBright,
  header: chalk.magentaBright,
  ip: chalk.yellowBright,
  length: chalk.cyanBright,
  protocol: chalk.gray,
  race: chalk.redBright,
  method: chalk.greenBright,
  unicode: chalk.whiteBright
};

function colorizeCategory(category, text) {
  const fn = categoryColor[category] || chalk.white;
  return fn(text);
}

if (argv.h) {
  console.log(`
${chalk.bold.red('403')} ${chalk.dim('— automated 403 bypass testing')}

${chalk.bold.underline('Usage')}: ${chalk.cyan('403 [options]')}

${chalk.bold.underline('Options')}:
  ${chalk.yellow('-t, --target')} ${chalk.dim('<url|file>')}   Target URL or file with URLs
  ${chalk.yellow('-x, --method')} ${chalk.dim('<method>')}     HTTP method ${chalk.dim('(default: GET)')}
  ${chalk.yellow('-H, --header')} ${chalk.dim('<header>')}     Custom headers ${chalk.dim('(e.g., "X-Forwarded-For: 127.0.0.1")')}
  ${chalk.yellow('-p, --path-payload')} ${chalk.dim('<path>')} Custom path payloads
  ${chalk.yellow('--port')} ${chalk.dim('<port>')}             Custom port
  ${chalk.yellow('--proxy')} ${chalk.dim('<proxy>')}           Proxy URL ${chalk.dim('(e.g., socks5://127.0.0.1:9050)')}
  ${chalk.yellow('--vct')}                    Show content type
  ${chalk.yellow('--vcl')}                    Show content length
  ${chalk.yellow('-c, --concurrency')} ${chalk.dim('<n>')}     Concurrent requests per target ${chalk.dim('(default: 15)')}
  ${chalk.yellow('--timeout')} ${chalk.dim('<ms>')}            Per-request timeout ${chalk.dim('(default: 10000)')}
  ${chalk.yellow('--delay')} ${chalk.dim('<ms>')}              Base delay before each request ${chalk.dim('(default: 0)')}
  ${chalk.yellow('--jitter')} ${chalk.dim('<ms>')}             Random extra delay 0-N ms ${chalk.dim('(default: 0)')}
  ${chalk.yellow('--no-progress')}            Disable the live progress indicator
  ${chalk.yellow('--up')}                     Update tool
  ${chalk.yellow('-h, --help')}                Show this help

${chalk.bold.underline('Test categories')} ${chalk.dim('(color legend for output)')}:
  ${colorizeCategory('path', '■')} Path manipulation      ${colorizeCategory('header', '■')} Header override        ${colorizeCategory('ip', '■')} IP spoofing
  ${colorizeCategory('length', '■')} Content-Length         ${colorizeCategory('protocol', '■')} Protocol downgrade     ${colorizeCategory('race', '■')} Race condition
  ${colorizeCategory('method', '■')} Method override        ${colorizeCategory('unicode', '■')} Unicode/encoding

${chalk.bold.underline('Result tags')}:
  ${chalk.bold.bgGreen.black(' BYPASS? ')} status changed from baseline AND body content differs — worth a manual look
  ${chalk.dim('[soft — identical body]')} status changed but the response body is byte-identical to baseline (likely a soft-403 page)
  ${chalk.dim('[similar body]')} status changed but body length is close to baseline (probably the same page)
`);
  process.exit(0);
}

if (argv.up) {
  console.log(chalk.cyan('Updating 403...'));
  const npm = spawn('npm', ['install', '-g', 'github:LocaMartin/403'], { stdio: 'inherit' });
  const code = await new Promise(resolve => { npm.on('close', resolve); });
  if (code === 0) console.log(chalk.green('Update complete.'));
  else console.log(chalk.red('Update failed.'));
  process.exit(code);
}

// ----------------------------------------------------------------------------
// Prepare targets list
// ----------------------------------------------------------------------------
let rawTargets = [];
if (argv.t) {
  if (fs.existsSync(argv.t) && fs.statSync(argv.t).isFile()) {
    rawTargets = fs.readFileSync(argv.t, 'utf8').split('\n').filter(Boolean);
  } else {
    rawTargets = [argv.t];
  }
} else {
  const rl = readline.createInterface({ input: process.stdin });
  rawTargets = await new Promise(resolve => {
    const lines = [];
    rl.on('line', line => lines.push(line));
    rl.on('close', () => resolve(lines.filter(Boolean)));
  });
}

if (rawTargets.length === 0) {
  console.error(chalk.red('No targets provided. Use -t or pipe URLs.'));
  process.exit(1);
}

// Validate targets up front so the progress total is accurate and bad lines
// don't blow up mid-run.
const targets = [];
for (const t of rawTargets) {
  try {
    new URL(t);
    targets.push(t.trim());
  } catch {
    console.error(chalk.yellow(`[!] Skipping invalid URL: ${t}`));
  }
}

if (targets.length === 0) {
  console.error(chalk.red('No valid targets after validation.'));
  process.exit(1);
}

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Tiny built-in concurrency limiter — no extra dependency needed.
function createLimiter(concurrency) {
  let active = 0;
  const queue = [];
  const runNext = () => {
    if (active >= concurrency || queue.length === 0) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    fn()
      .then(resolve, reject)
      .finally(() => {
        active--;
        runNext();
      });
  };
  return function limit(fn) {
    return new Promise((resolve, reject) => {
      queue.push({ fn, resolve, reject });
      runNext();
    });
  };
}

function colorizeStatus(status) {
  if (status >= 200 && status < 300) return chalk.bold.green(status);
  if (status >= 300 && status < 400) return chalk.bold.cyan(status);
  if (status >= 400 && status < 500) return chalk.bold.red(status);
  if (status >= 500) return chalk.bold.yellow(status);
  return chalk.bold.blue(status);
}

function classifyError(err) {
  if (err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '')) {
    return { label: 'TIMEOUT', colored: chalk.bold.yellow('TIMEOUT') };
  }
  if (err.code === 'ETIMEDOUT') {
    return { label: 'TIMEOUT', colored: chalk.bold.yellow('TIMEOUT') };
  }
  if (err.code === 'ECONNRESET') {
    return { label: 'RESET', colored: chalk.bold.magenta('RESET') };
  }
  if (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN') {
    return { label: 'DNS', colored: chalk.bold.blue('DNS') };
  }
  if (err.code === 'ECONNREFUSED') {
    return { label: 'REFUSED', colored: chalk.bold.red('REFUSED') };
  }
  return { label: 'ERROR', colored: chalk.red('ERROR') };
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
    method,
    url: targetUrl,
    headers: customHeaders,
    maxRedirects: 0,
    validateStatus: () => true,
    timeout: argv.timeout,
    responseType: 'arraybuffer', // raw bytes — consistent length/hash regardless of content-type
    httpAgent: null,
    httpsAgent: null
  };

  if (proxyUrl) {
    const ProxyAgent = proxyUrl.startsWith('socks') ? SocksProxyAgent : HttpsProxyAgent;
    const agent = new ProxyAgent(proxyUrl);
    if (url.protocol === 'https:') configReq.httpsAgent = agent;
    else configReq.httpAgent = agent;
  }

  if (customPort) {
    url.port = customPort;
    configReq.url = url.toString();
  }

  return configReq;
}

function hashBody(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}

// Real HTTP/0.9 downgrade: a headerless raw request over a bare socket.
// HTTP/0.9 has no status line and no headers — just a request line in,
// raw body out. Useful for spotting origins/proxies that mishandle a
// request with no Host header at all.
function httpZeroNineRequest(targetUrl, method, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl);
    const isHttps = url.protocol === 'https:';
    const port = Number(url.port) || (isHttps ? 443 : 80);
    const requestLine = `${method} ${url.pathname}${url.search} HTTP/0.9\r\n\r\n`;

    const connectOpts = { host: url.hostname, port };
    const socket = isHttps
      ? tls.connect({ ...connectOpts, servername: url.hostname, rejectUnauthorized: false })
      : net.connect(connectOpts);

    let data = Buffer.alloc(0);
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(Object.assign(new Error('HTTP/0.9 request timed out'), { code: 'ETIMEDOUT' }));
    }, timeoutMs);

    const onConnect = () => socket.write(requestLine);
    socket.on(isHttps ? 'secureConnect' : 'connect', onConnect);
    socket.on('data', chunk => { data = Buffer.concat([data, chunk]); });

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ body: data, length: data.length });
    };
    socket.on('end', finish);
    socket.on('close', finish);

    socket.on('error', err => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ----------------------------------------------------------------------------
// Test generation (uses config loaded from YAML)
// ----------------------------------------------------------------------------
function generateTests(target, customPathPayloads = []) {
  const baseUrl = new URL(target);
  const originalPath = baseUrl.pathname;
  const tests = [];

  function addTest(category, description, url, headers = {}, method = argv.x, extra = {}) {
    tests.push({ category, description, url, headers, method, ...extra });
  }

  const allPathPayloads = [...config.path_payloads, ...customPathPayloads];
  for (const payload of allPathPayloads) {
    const newPath = originalPath + payload;
    const url = new URL(baseUrl);
    url.pathname = newPath;
    addTest('path', `Path: ${payload}`, url.toString());
  }

  for (const [header, valueTemplate] of Object.entries(config.override_headers)) {
    const value = valueTemplate.replace('{}', originalPath);
    const headers = { [header]: value };
    const url = new URL(baseUrl);
    url.pathname = '/';
    addTest('header', `Header override: ${header}`, url.toString(), headers);
  }

  for (const ipHeader of config.ip_bypass_headers) {
    for (const ipValue of config.ip_values) {
      const headers = { [ipHeader]: ipValue };
      addTest('ip', `IP spoof: ${ipHeader}: ${ipValue}`, target, headers);
    }
  }

  const clTests = [
    { desc: 'Content-Length: 0', headers: { 'Content-Length': '0' } },
    { desc: 'Content-Length: -1', headers: { 'Content-Length': '-1' } },
    { desc: 'Content-Length: 9999999999', headers: { 'Content-Length': '9999999999' } }
  ];
  for (const t of clTests) {
    addTest('length', `Content-Length: ${t.desc}`, target, t.headers, argv.x);
  }

  // Real HTTP/0.9 downgrade over a raw socket (see httpZeroNineRequest).
  addTest('protocol', 'HTTP/0.9 downgrade', target, {}, argv.x, { raw: true });

  const racePath = originalPath + originalPath;
  const raceUrl = new URL(baseUrl);
  raceUrl.pathname = racePath;
  addTest('race', 'Race condition (path doubling)', raceUrl.toString());

  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD'];
  for (const m of methods) {
    if (m !== argv.x) addTest('method', `Method override: ${m}`, target, {}, m);
  }

  const unicodeTests = [
    { desc: 'Unicode homoglyph (admin → аdmin)', path: originalPath.replace(/a/g, 'а') },
    { desc: 'Case variation', path: originalPath.split('/').map(p => p.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('')).join('/') },
    { desc: 'Double URL encode', path: originalPath.split('/').map(p => encodeURIComponent(encodeURIComponent(p))).join('/') }
  ];
  for (const t of unicodeTests) {
    const url = new URL(baseUrl);
    url.pathname = t.path;
    addTest('unicode', t.desc, url.toString());
  }

  return tests;
}

// ----------------------------------------------------------------------------
// Progress indicator (stderr, so it never pollutes piped stdout output)
// ----------------------------------------------------------------------------
function makeProgress(totalAll) {
  let done = 0;
  const start = Date.now();
  return {
    tick(targetLabel, targetIdx, targetTotal) {
      done++;
      if (!argv.progress) return;
      const pct = totalAll === 0 ? 100 : Math.floor((done / totalAll) * 100);
      const elapsed = ((Date.now() - start) / 1000).toFixed(0);
      const line = `\r${chalk.dim('[»] Progress:')} ${done}/${totalAll} (${pct}%) ${chalk.dim(`| target ${targetIdx}/${targetTotal}`)} ${chalk.dim(`| ${elapsed}s`)} ${chalk.dim(targetLabel)}`;
      process.stderr.write(line.padEnd(process.stderr.columns || 100));
    },
    done() {
      if (!argv.progress) return;
      process.stderr.write('\n');
    }
  };
}

// ----------------------------------------------------------------------------
// Body similarity tagging vs baseline
// ----------------------------------------------------------------------------
function similarityTag(baseline, status, bodyBuf) {
  if (!baseline || status === baseline.status) return '';
  const hash = hashBody(bodyBuf);
  if (hash === baseline.hash) return chalk.dim(' [soft — identical body]');
  const lenDiffRatio = baseline.length === 0 ? 1 : Math.abs(bodyBuf.length - baseline.length) / baseline.length;
  if (lenDiffRatio < 0.1) return chalk.dim(' [similar body]');
  return chalk.bold.bgGreen.black(' BYPASS? ');
}

// ----------------------------------------------------------------------------
// Main execution
// ----------------------------------------------------------------------------
(async () => {
  const customHeaders = parseHeaders(argv.H || []);
  const customPathPayloads = argv.p || [];

  // Precompute per-target test lists + overall total for the progress bar.
  const targetPlans = targets.map(target => ({
    target,
    tests: generateTests(target, customPathPayloads)
  }));
  const totalAll = targetPlans.reduce((sum, p) => sum + p.tests.length, 0);
  const progress = makeProgress(totalAll);

  for (let ti = 0; ti < targetPlans.length; ti++) {
    const { target, tests } = targetPlans[ti];
    console.log(chalk.bold.cyan(`\n[>] Testing: `) + chalk.underline(target));

    // Fetch baseline (real request, no payload) for status/body comparison.
    let baseline = null;
    try {
      const baseConfig = buildRequestConfig(target, argv.x, customHeaders, argv.proxy, argv.port);
      const baseResp = await axios(baseConfig);
      const buf = Buffer.from(baseResp.data);
      baseline = { status: baseResp.status, length: buf.length, hash: hashBody(buf) };
      console.log(chalk.dim(`  [i] Baseline: ${colorizeStatus(baseline.status)} ${chalk.dim(`(${baseline.length} bytes)`)}`));
    } catch (err) {
      const { colored } = classifyError(err);
      console.log(chalk.yellow(`  [!] Baseline fetch failed (${colored}) — body similarity checks disabled for this target`));
    }

    const limit = createLimiter(argv.concurrency);

    const runOne = async (test) => {
      if (argv.delay || argv.jitter) {
        const wait = argv.delay + (argv.jitter > 0 ? Math.floor(Math.random() * argv.jitter) : 0);
        if (wait > 0) await sleep(wait);
      }

      if (test.raw) {
        try {
          const { body } = await httpZeroNineRequest(test.url, test.method, argv.timeout);
          const label = body.length > 0 ? chalk.bold.cyan(`RAW(${body.length}B)`) : chalk.dim('RAW(0B)');
          const descColored = colorizeCategory(test.category, test.description);
          console.log(`  ${label} – ${descColored} [${test.method}] ${chalk.dim(test.url)}`);
        } catch (err) {
          const { colored } = classifyError(err);
          console.log(chalk.red(`  ${chalk.bold(colored)} – ${test.description} [${test.method}] ${test.url} – ${chalk.dim(err.message)}`));
        }
        return;
      }

      try {
        const configReq = buildRequestConfig(test.url, test.method, { ...customHeaders, ...test.headers }, argv.proxy, argv.port);
        const response = await axios(configReq);
        const buf = Buffer.from(response.data);

        const status = response.status;
        const statusColored = colorizeStatus(status);
        const contentType = response.headers['content-type'] || 'N/A';
        const contentLength = response.headers['content-length'] || buf.length;
        const tag = similarityTag(baseline, status, buf);

        const methodColored = chalk.bold.white(`[${test.method}]`);
        const descColored = colorizeCategory(test.category, test.description);
        const urlColored = chalk.dim(test.url);

        let output = `  ${statusColored} – ${descColored} ${methodColored} ${urlColored}${tag}`;
        if (argv.vct) output += chalk.dim(` | Type: `) + chalk.white(contentType);
        if (argv.vcl) output += chalk.dim(` | Length: `) + chalk.white(contentLength);
        console.log(output);
      } catch (err) {
        const { colored } = classifyError(err);
        console.log(chalk.red(`  ${chalk.bold(colored)} – ${test.description} [${test.method}] ${test.url} – ${chalk.dim(err.message)}`));
      }
    };

    await Promise.all(
      tests.map(test =>
        limit(async () => {
          await runOne(test);
          progress.tick(target, ti + 1, targetPlans.length);
        })
      )
    );
  }

  progress.done();
  console.log(chalk.bold.green('\n[*] Testing complete.'));
})();