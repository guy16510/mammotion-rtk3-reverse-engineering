#!/usr/bin/env node
'use strict';
import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2];
if (!root) { console.error('Usage: node analyze.js <capture-directory>'); process.exit(2); }

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}
function crc24q(buffer) {
  let crc = 0;
  for (const byte of buffer) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i += 1) { crc <<= 1; if (crc & 0x1000000) crc ^= 0x1864cfb; }
  }
  return crc & 0xffffff;
}
function findRtcm3(buf) {
  const frames = [];
  for (let i = 0; i + 6 <= buf.length; i += 1) {
    if (buf[i] !== 0xd3) continue;
    const length = ((buf[i + 1] & 0x03) << 8) | buf[i + 2];
    const total = 3 + length + 3;
    if (length > 1023 || i + total > buf.length) continue;
    const expected = (buf[i + total - 3] << 16) | (buf[i + total - 2] << 8) | buf[i + total - 1];
    const actual = crc24q(buf.subarray(i, i + total - 3));
    if (actual !== expected) continue;
    const type = length >= 2 ? ((buf[i + 3] << 4) | (buf[i + 4] >> 4)) : null;
    frames.push({ offset: i, length, type }); i += total - 1;
  }
  return frames;
}
function countPattern(buf, pattern) {
  let count = 0;
  for (let i = 0; i <= buf.length - pattern.length; i += 1) {
    let match = true;
    for (let j = 0; j < pattern.length; j += 1) if (buf[i + j] !== pattern[j]) { match = false; break; }
    if (match) count += 1;
  }
  return count;
}
function entropy(buf) {
  if (!buf.length) return 0;
  const counts = new Array(256).fill(0); for (const b of buf) counts[b] += 1;
  return counts.reduce((sum, n) => { if (!n) return sum; const p = n / buf.length; return sum - p * Math.log2(p); }, 0);
}
function printableRatio(buf) {
  if (!buf.length) return 0;
  let printable = 0; for (const b of buf) if ((b >= 32 && b <= 126) || [9,10,13].includes(b)) printable += 1;
  return printable / buf.length;
}

const rawDir = path.join(root, 'raw');
const files = walk(rawDir);
const binaryFiles = files.filter(f => f.endsWith('.bin'));
const pcapFiles = files.filter(f => f.endsWith('.pcap') || f.endsWith('.pcapng'));
const serialResults = binaryFiles.map(file => {
  const buf = fs.readFileSync(file); const frames = findRtcm3(buf);
  return { file: path.relative(root, file), bytes: buf.length, rtcmFrames: frames.length,
    rtcmTypes: [...new Set(frames.map(f => f.type).filter(v => v !== null))].sort((a,b) => a-b),
    ubxSync: countPattern(buf, Buffer.from([0xb5,0x62])),
    nmea: countPattern(buf, Buffer.from('$GN')) + countPattern(buf, Buffer.from('$GP')),
    entropy: entropy(buf), printable: printableRatio(buf) };
});
const useful = serialResults.filter(r => r.bytes > 0).sort((a,b) => (b.rtcmFrames-a.rtcmFrames) || (b.bytes-a.bytes));

console.log('# Mammotion RTK3 capture summary\n');
console.log(`Capture directory: \`${root}\``); console.log(`Generated: ${new Date().toISOString()}\n`);
console.log('## Automated findings\n');
if (!binaryFiles.length) console.log('- No serial binary captures were found.');
else if (!useful.length) console.log('- Serial devices were detected, but no bytes were captured.');
else {
  const rtcmTotal = useful.reduce((s,r)=>s+r.rtcmFrames,0), ubxTotal = useful.reduce((s,r)=>s+r.ubxSync,0), nmeaTotal = useful.reduce((s,r)=>s+r.nmea,0);
  console.log(`- Captured data from ${useful.length} serial sample(s).`);
  console.log(`- Valid RTCM3 frames: **${rtcmTotal}**.`);
  console.log(`- u-blox UBX sync markers: **${ubxTotal}**.`);
  console.log(`- NMEA sentence prefixes: **${nmeaTotal}**.`);
}
console.log('\n## Serial samples\n');
if (useful.length) {
  console.log('| File | Bytes | RTCM3 | Types | UBX | NMEA | Entropy | Printable |');
  console.log('|---|---:|---:|---|---:|---:|---:|---:|');
  for (const r of useful) console.log(`| \`${r.file}\` | ${r.bytes} | ${r.rtcmFrames} | ${r.rtcmTypes.join(', ') || '-'} | ${r.ubxSync} | ${r.nmea} | ${r.entropy.toFixed(2)} | ${(r.printable*100).toFixed(1)}% |`);
} else console.log('No non-empty serial samples.');
console.log('\n## Network artifacts\n');
if (pcapFiles.length) for (const f of pcapFiles) console.log(`- \`${path.relative(root,f)}\`, ${fs.statSync(f).size} bytes`);
else console.log('- No PCAP was produced.');
console.log('\n## Recommended next action\n');
const top = useful[0];
if (top?.rtcmFrames) console.log(`Use \`${top.file}\` as the initial RTCM source.`);
else if (top?.ubxSync) console.log(`Decode \`${top.file}\` as u-blox UBX traffic.`);
else if (top?.nmea) console.log(`Probe the opposite UART direction from \`${top.file}\` to find corrections.`);
else if (top) console.log(`Compare repeated captures beginning with \`${top.file}\`.`);
else console.log('Verify receive-only UART wiring and rerun.');
