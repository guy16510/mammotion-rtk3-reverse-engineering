#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const ROOT = path.resolve(process.env.RTK3_ROOT || process.cwd());
const CAPTURE_ROOT = path.resolve(process.env.RTK3_CAPTURE_ROOT || path.join(ROOT, 'rtk3-captures'));
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const TOKEN = process.env.MCP_BEARER_TOKEN || '';
const ALLOWED_TARGETS = new Set((process.env.RTK3_ALLOWED_TARGETS || '').split(',').map(v => v.trim()).filter(Boolean));
const MAX_CAPTURE_SECONDS = Number(process.env.RTK3_MAX_CAPTURE_SECONDS || 1800);
const jobs = new Map();

function text(value) {
  return { content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }] };
}

function safeName(value) {
  if (!/^[A-Za-z0-9._-]+$/.test(value)) throw new Error('Invalid capture name');
  return value;
}

function isPrivateIp(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
}

function assertAllowedTarget(ip) {
  if (!isPrivateIp(ip)) throw new Error('Only IPv4 private-network targets are allowed');
  if (ALLOWED_TARGETS.size && !ALLOWED_TARGETS.has(ip)) throw new Error('Target is not in RTK3_ALLOWED_TARGETS');
}

async function captures() {
  await fs.mkdir(CAPTURE_ROOT, { recursive: true });
  const entries = await fs.readdir(CAPTURE_ROOT, { withFileTypes: true });
  const rows = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(CAPTURE_ROOT, entry.name);
    const stat = await fs.stat(dir);
    rows.push({ name: entry.name, modified: stat.mtime.toISOString(), summary: fsSync.existsSync(path.join(dir, 'summary.md')) });
  }
  return rows.sort((a, b) => b.modified.localeCompare(a.modified));
}

function makeServer() {
  const server = new McpServer({ name: 'mammotion-rtk3-probe', version: '0.2.0' });

  server.tool('rtk3_health', 'Return MCP host health and configured safety boundaries.', {}, async () => text({
    ok: true,
    root: ROOT,
    captureRoot: CAPTURE_ROOT,
    allowedTargets: [...ALLOWED_TARGETS],
    maxCaptureSeconds: MAX_CAPTURE_SECONDS,
    activeJobs: [...jobs.values()].filter(j => j.status === 'running').length
  }));

  server.tool('rtk3_list_captures', 'List capture directories and whether each has a generated summary.', {}, async () => text(await captures()));

  server.tool('rtk3_read_summary', 'Read one generated capture summary.', {
    capture: z.string().describe('Exact capture directory name returned by rtk3_list_captures')
  }, async ({ capture }) => {
    const name = safeName(capture);
    const file = path.join(CAPTURE_ROOT, name, 'summary.md');
    const body = await fs.readFile(file, 'utf8');
    return text(body.slice(0, 100000));
  });

  server.tool('rtk3_job_status', 'Return the status of a capture job started by this MCP process.', {
    jobId: z.string().uuid()
  }, async ({ jobId }) => text(jobs.get(jobId) || { jobId, status: 'unknown' }));

  server.tool('rtk3_start_capture', 'Start the approved passive capture bundle. It creates logs and PCAP files but does not transmit on UART.', {
    targetIp: z.string().optional().describe('Optional private IPv4 address of the RTK'),
    durationSeconds: z.number().int().min(30).max(MAX_CAPTURE_SECONDS).default(300),
    serialDevices: z.string().regex(/^(auto|\/dev\/[A-Za-z0-9_./,-]+)$/).default('auto'),
    runBle: z.boolean().default(true),
    runNmap: z.boolean().default(true),
    runSerial: z.boolean().default(true),
    runPcap: z.boolean().default(true)
  }, async ({ targetIp, durationSeconds, serialDevices, runBle, runNmap, runSerial, runPcap }) => {
    if (targetIp) assertAllowedTarget(targetIp);
    const jobId = crypto.randomUUID();
    const logDir = path.join(CAPTURE_ROOT, '_mcp-jobs');
    await fs.mkdir(logDir, { recursive: true });
    const logPath = path.join(logDir, `${jobId}.log`);
    const fd = fsSync.openSync(logPath, 'a');
    const env = {
      ...process.env,
      OUTPUT_ROOT: CAPTURE_ROOT,
      INSTALL_DEPS: '0',
      TARGET_IP: targetIp || '',
      DURATION: String(durationSeconds),
      SERIAL_DEVICES: serialDevices,
      RUN_BLE: runBle ? '1' : '0',
      RUN_NMAP: runNmap ? '1' : '0',
      RUN_SERIAL: runSerial ? '1' : '0',
      RUN_PCAP: runPcap ? '1' : '0'
    };
    const child = spawn('bash', [path.join(ROOT, 'capture.sh')], { cwd: ROOT, env, detached: false, stdio: ['ignore', fd, fd] });
    const job = { jobId, pid: child.pid, status: 'running', startedAt: new Date().toISOString(), logPath, targetIp: targetIp || null, durationSeconds };
    jobs.set(jobId, job);
    child.on('exit', (code, signal) => {
      fsSync.closeSync(fd);
      Object.assign(job, { status: code === 0 ? 'completed' : 'failed', exitCode: code, signal, finishedAt: new Date().toISOString() });
    });
    child.on('error', error => Object.assign(job, { status: 'failed', error: error.message, finishedAt: new Date().toISOString() }));
    return text(job);
  });

  server.tool('rtk3_probe_target', 'Run a bounded TCP connect scan against one allowlisted private IPv4 target.', {
    targetIp: z.string(),
    ports: z.array(z.number().int().min(1).max(65535)).max(32).default([22, 53, 80, 443, 1883, 8883, 8080, 8443])
  }, async ({ targetIp, ports }) => {
    assertAllowedTarget(targetIp);
    const uniquePorts = [...new Set(ports)];
    const args = ['-Pn', '-sT', '--host-timeout', '60s', '-p', uniquePorts.join(','), targetIp];
    const result = await new Promise((resolve, reject) => {
      const child = spawn('nmap', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 100000) child.kill(); });
      child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 20000) child.kill(); });
      child.on('error', reject);
      child.on('exit', code => resolve({ code, stdout, stderr }));
    });
    return text(result);
  });

  return server;
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.get('/healthz', (_req, res) => res.json({ ok: true }));
app.use('/mcp', (req, res, next) => {
  if (!TOKEN) return res.status(503).json({ error: 'MCP_BEARER_TOKEN is not configured' });
  const supplied = req.headers.authorization || '';
  const expected = `Bearer ${TOKEN}`;
  const valid = supplied.length === expected.length && crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
  if (!valid) return res.status(401).json({ error: 'Unauthorized' });
  next();
});
app.all('/mcp', async (req, res) => {
  const server = makeServer();
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close().catch(() => {}); server.close().catch(() => {}); });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, HOST, () => console.log(`RTK3 MCP listening on http://${HOST}:${PORT}/mcp`));
