// 하찮은 RPG 멀티플레이 서버 (설치할 패키지 없음: node server.js 만 실행하면 돼요)
// 게임 파일(public/index.html)도 같이 내보내고, 같은 주소의 웹소켓으로 접속자끼리 상태를 중계해요.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const MAX_PLAYERS = 40;
const MAX_STATE_BYTES = 8 * 1024;
const MAX_FRAME = 16 * 1024;
const TICK_MS = 33;
const INDEX = fs.existsSync(path.join(__dirname, 'index.html')) ? path.join(__dirname, 'index.html') : path.join(__dirname, 'public', 'index.html');
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const clients = new Set();
let dirty = false;

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/' || url === '/index.html') {
    fs.readFile(INDEX, (err, data) => {
      if (err) { res.writeHead(500); res.end('index.html not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      res.end(data);
    });
  } else if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok ' + clients.size);
  } else {
    res.writeHead(404); res.end('not found');
  }
});

/* ---------- 최소 웹소켓 구현 (RFC 6455) ---------- */
function frame(op, payload) {
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | op, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([head, payload]);
}
function sendText(c, str) {
  if (c.closed || c.socket.writableLength > 1024 * 1024) return;
  c.socket.write(frame(0x1, Buffer.from(str)));
}
function closeClient(c, code) {
  if (c.closed) return;
  c.closed = true;
  clients.delete(c);
  dirty = true;
  try {
    const p = Buffer.alloc(2); p.writeUInt16BE(code || 1000, 0);
    c.socket.end(frame(0x8, p));
  } catch (e) { /* 이미 닫힘 */ }
  setTimeout(() => c.socket.destroy(), 500);
}

function onMessage(c, text) {
  const now = Date.now();
  if (now - c.t > 1000) { c.t = now; c.n = 0; }
  if (++c.n > 60) return; // 초당 60개 넘으면 무시
  let m;
  try { m = JSON.parse(text); } catch (e) { return; }
  if (!m || m.t !== 'p' || !m.d || typeof m.d !== 'object' || Array.isArray(m.d)) return;
  const next = Object.assign({}, c.p);
  for (const k of Object.keys(m.d)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,15}$/.test(k)) continue;
    if (m.d[k] === null) delete next[k]; else next[k] = m.d[k];
  }
  if (Buffer.byteLength(JSON.stringify(next)) > MAX_STATE_BYTES) return;
  c.p = next;
  dirty = true;
}

function parse(c) {
  for (;;) {
    const b = c.buf;
    if (b.length < 2) return;
    const fin = (b[0] & 0x80) !== 0, op = b[0] & 0x0f, masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; const big = b.readBigUInt64BE(2); if (big > BigInt(MAX_FRAME)) return closeClient(c, 1009); len = Number(big); off = 10; }
    if (!masked || len > MAX_FRAME) return closeClient(c, 1002);
    if (b.length < off + 4 + len) return;
    const mask = b.subarray(off, off + 4);
    const data = Buffer.from(b.subarray(off + 4, off + 4 + len));
    for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
    c.buf = b.subarray(off + 4 + len);
    if (op === 0x8) return closeClient(c, 1000);
    if (op === 0x9) { c.socket.write(frame(0xA, data)); continue; }
    if (op === 0xA) { c.alive = true; continue; }
    if (op === 0x1 || op === 0x0) {
      if (op === 0x1) c.frag = [];
      if (!c.frag) return closeClient(c, 1002);
      c.frag.push(data);
      if (c.frag.reduce((s, x) => s + x.length, 0) > MAX_FRAME) return closeClient(c, 1009);
      if (fin) { const text = Buffer.concat(c.frag).toString('utf8'); c.frag = null; onMessage(c, text); }
      continue;
    }
    // 바이너리 등은 지원하지 않아요
    return closeClient(c, 1003);
  }
}

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  if (clients.size >= MAX_PLAYERS) { socket.end('HTTP/1.1 503 Service Unavailable\r\n\r\n'); return; }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  const c = { socket, id: crypto.randomBytes(5).toString('hex'), p: {}, alive: true, n: 0, t: Date.now(), buf: Buffer.alloc(0), frag: null, closed: false };
  clients.add(c);
  sendText(c, JSON.stringify({ t: 'hi', id: c.id }));
  dirty = true;
  socket.on('data', (d) => { if (c.closed) return; c.buf = Buffer.concat([c.buf, d]); parse(c); });
  socket.on('close', () => { c.closed = true; clients.delete(c); dirty = true; });
  socket.on('error', () => { /* close 이벤트에서 정리돼요 */ });
});

setInterval(() => {
  if (!dirty) return;
  dirty = false;
  const peers = [];
  for (const c of clients) peers.push({ i: c.id, p: c.p });
  const msg = JSON.stringify({ t: 's', peers });
  for (const c of clients) sendText(c, msg);
}, TICK_MS);

setInterval(() => { // 응답 없는 접속 정리
  for (const c of clients) {
    if (!c.alive) { c.socket.destroy(); continue; }
    c.alive = false;
    try { c.socket.write(frame(0x9, Buffer.alloc(0))); } catch (e) { /* ignore */ }
  }
}, 15000);

server.listen(PORT, () => console.log('하찮은 RPG 서버 실행 중: http://localhost:' + PORT));
