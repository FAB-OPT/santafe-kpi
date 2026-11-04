#!/usr/bin/env node
/* เข้ารหัสข้อมูลรายงาน 401 (รายการวัตถุดิบ) ให้เว็บ KPI ใช้ — ไม่เก็บรหัสไว้ที่ไหน
   ใช้:  node tools/encrypt-cogs.js [ไฟล์ cogs-401.html] [ไฟล์ปลายทาง]
   ค่าเริ่มต้น: 401/cogs-401_1.html → cogs401.enc.json  (รหัส = รหัสเดียวกับที่ใช้เข้าเว็บ) */
const fs = require('fs'), zlib = require('zlib'), crypto = require('crypto');
const src = process.argv[2] || '401/cogs-401_1.html', out = process.argv[3] || 'cogs401.enc.json';

function ask(q) {
  return new Promise(res => {
    if (process.env.COGS_PASS) return res(process.env.COGS_PASS);
    process.stdout.write(q);
    const si = process.stdin; let buf = '';
    if (si.isTTY) si.setRawMode(true);
    si.resume(); si.setEncoding('utf8');
    si.on('data', function on(ch) {
      for (const c of ch) {
        if (c === '\r' || c === '\n') { if (si.isTTY) si.setRawMode(false); si.pause(); si.removeListener('data', on); process.stdout.write('\n'); return res(buf); }
        if (c === '\u0003') process.exit(1);
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1); else buf += c;
      }
    });
  });
}

(async () => {
  const html = fs.readFileSync(src, 'utf8');
  const tag = '<script id="data" type="application/json">';
  const i = html.indexOf(tag); if (i < 0) throw new Error('ไม่พบข้อมูลในไฟล์ ' + src);
  const j = html.indexOf('</script>', i);
  const raw = html.slice(i + tag.length, j);
  const data = JSON.parse(raw);                     // ตรวจว่าเป็น JSON ถูกต้อง
  /* ตรวจรหัสกับข้อมูลหลักของเว็บ (index.html) ก่อนเข้ารหัส — กันพิมพ์ผิด/ลืมสลับเป็นแป้นภาษาอังกฤษ */
  const idx = fs.readFileSync(__dirname + '/../index.html', 'utf8');
  const m = idx.match(/const ENC=\{s:'([^']+)',i:'([^']+)',c:'([^']+)',n:(\d+)\}/);
  const check = p => { if (!m) return true; try {
      const k = crypto.pbkdf2Sync(p, Buffer.from(m[1], 'base64'), +m[4], 32, 'sha256'), buf = Buffer.from(m[3], 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', k, Buffer.from(m[2], 'base64')); d.setAuthTag(buf.slice(buf.length - 16));
      d.update(buf.slice(0, buf.length - 16)); d.final(); return true; } catch (e) { return false; } };
  let pass = '';
  for (let t = 0; t < 3; t++) {
    pass = (await ask('รหัสผ่านเว็บ KPI: ')).trim();
    if (!pass) throw new Error('ไม่ได้ใส่รหัส');
    if (check(pass)) break;
    if (process.env.COGS_PASS || t === 2) throw new Error('รหัสไม่ตรงกับรหัสเข้าเว็บ — ตรวจแป้นพิมพ์ว่าเป็นภาษาอังกฤษ/ไม่มีช่องว่าง แล้วรันใหม่');
    console.log('รหัสไม่ตรงกับรหัสเข้าเว็บ — พิมพ์ใหม่อีกครั้ง (ตรวจแป้นพิมพ์ว่าเป็นภาษาอังกฤษ)');
  }
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12), n = 200000;
  const key = crypto.pbkdf2Sync(pass, salt, n, 32, 'sha256');
  const z = zlib.gzipSync(Buffer.from(JSON.stringify(data), 'utf8'), { level: 9 });
  const ci = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([ci.update(z), ci.final(), ci.getAuthTag()]);   // WebCrypto ต่อแท็ก 16 ไบต์ท้ายข้อมูล
  fs.writeFileSync(out, JSON.stringify({ s: salt.toString('base64'), i: iv.toString('base64'), n, z: 1, c: enc.toString('base64') }));
  console.log('เสร็จ: ' + out + ' (' + (fs.statSync(out).size / 1024).toFixed(0) + ' KB) · ' + data.months.map(m => m.short).join(', '));
})().catch(e => { console.error('ผิดพลาด: ' + e.message); process.exit(1); });
