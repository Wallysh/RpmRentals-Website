const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const multer = require('multer'), { Pool } = require('pg'), nodemailer = require('nodemailer'), webpush = require('web-push');
const E = process.env;
if (!E.ADMIN_PASSWORD || !E.SESSION_SECRET || !E.DATABASE_URL) { console.error('Set ADMIN_PASSWORD, SESSION_SECRET and DATABASE_URL (see README)'); process.exit(1); }

const pool = new Pool({ connectionString: E.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
const all = async (sql, p) => (await pool.query(sql, p)).rows;
const one = async (sql, p) => (await all(sql, p))[0];
const ready = pool.query(`
create table if not exists bookings(
  id serial primary key, token text unique, created text, status text default 'pending',
  vehicle text, schedule text, customer text, id_file text, id_back text, id_app text, signature text,
  signed_at text, ip text, ua text, agreement_hash text, agreement_text text);
create table if not exists vehicles(id serial primary key, name text, rego text, daily_rate text, bond text, excess text, image text, created text, type text);
create table if not exists files(name text primary key, mime text, data bytea);
create table if not exists settings(key text primary key, value text);
create table if not exists push_subs(endpoint text primary key, data text, created text);
create table if not exists requests(id serial primary key, created text, status text default 'new', vehicle_id int, vehicle_name text, pickup text, ret text, name text, mobile text, email text, notes text, booking_id int, ip text);
alter table vehicles add column if not exists listed text default 'yes';
alter table bookings add column if not exists tracker text;
alter table bookings add column if not exists link_expires text;
alter table bookings add column if not exists prefill text;
alter table bookings add column if not exists charges text;
alter table bookings add column if not exists cancelled_at text;
alter table bookings add column if not exists cancel_note text;
create table if not exists condition_reports(id serial primary key, booking_id int, stage text, reading text, fuel text, notes text, photos text, created text);`);

const agFiles = {};
function agText(f) { if (!fs.existsSync(path.join(__dirname, f))) f = 'agreement.txt'; if (!agFiles[f]) agFiles[f] = fs.readFileSync(path.join(__dirname, f), 'utf8'); return agFiles[f]; }
function itemsOf(s) { return Array.isArray(s.items) && s.items.length ? s.items : [{ name: s.vehicle, type: s.itemType || 'Car', rego: s.rego, image: s.carImage }]; }
function agreementFor(s) {
  const it = itemsOf(s), parts = [];
  if (it.some(i => i.type !== 'Jet ski')) parts.push(['VEHICLE HIRE', agText('agreement.txt')]);
  if (it.some(i => i.type === 'Jet ski')) parts.push(['JET SKI HIRE', agText('agreement-jetski.txt')]);
  const text = parts.length > 1 ? parts.map(([t, x]) => '########## ' + t + ' AGREEMENT ##########\\n\\n' + x).join('\\n\\n\\n') : parts[0][1];
  return { text, hash: crypto.createHash('sha256').update(text).digest('hex') };
}
const mail = E.SMTP_HOST ? nodemailer.createTransport({ host: E.SMTP_HOST, port: +E.SMTP_PORT || 587,
  auth: { user: E.SMTP_USER, pass: E.SMTP_PASS } }) : null;

const sign = v => crypto.createHmac('sha256', E.SESSION_SECRET).update(v).digest('hex');
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const isAdmin = q => { const m = /(?:^|; )s=([^;]+)/.exec(q.headers.cookie || ''); return !!m && same(m[1], sign('admin')); };
const auth = (q, r, n) => isAdmin(q) ? n() : r.status(401).json({ error: 'Not logged in' });
const A = fn => (q, r, n) => Promise.resolve(fn(q, r, n)).catch(e => { console.error(e); if (!r.headersSent) r.status(500).json({ error: 'Server error, please try again.' }); });
const num = v => parseInt(v, 10) || 0;

const mem = { storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (q, f, cb) => cb(null, /^image\//.test(f.mimetype)) };
const upload = multer(mem);
const saveFile = async f => {
  const name = crypto.randomBytes(16).toString('hex') + path.extname(f.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
  await pool.query('insert into files(name,mime,data) values($1,$2,$3)', [name, f.mimetype, f.buffer]);
  return name;
};
const sendFile = async (name, r) => {
  const f = name && await one('select mime,data from files where name=$1', [path.basename(name)]);
  if (!f) return r.sendStatus(404);
  r.set('Cache-Control', 'private, max-age=3600'); r.type(f.mime).send(f.data);
};

const app = express();
app.set('trust proxy', 1);
app.use((q, r, n) => { r.set({ 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' }); if (q.path !== '/' && q.path !== '/robots.txt') r.set('X-Robots-Tag', 'noindex'); n(); });
app.use(express.json({ limit: '100kb' }));
app.get('/', (q, r) => r.sendFile(path.join(__dirname, 'site.html')));
app.get('/robots.txt', (q, r) => r.type('text/plain').send('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /s/\nDisallow: /api/\nDisallow: /record/\n'));
app.get('/admin', (q, r) => r.sendFile(path.join(__dirname, 'admin.html')));
app.get('/s/:token', (q, r) => r.sendFile(path.join(__dirname, 'sign.html')));
app.get('/logo.jpg', (q, r) => r.sendFile(path.join(__dirname, 'logo.jpg')));
app.get('/logo-wide.jpg', (q, r) => r.sendFile(path.join(__dirname, 'logo-wide.jpg')));
app.get('/manifest.webmanifest', (q, r) => { r.type('application/manifest+json'); r.sendFile(path.join(__dirname, 'manifest.webmanifest')); });
for (const f of ['icon-192.png', 'icon-512.png', 'apple-touch-icon.png']) app.get('/' + f, (q, r) => r.sendFile(path.join(__dirname, f)));
app.get('/sw.js', (q, r) => { r.set({ 'Service-Worker-Allowed': '/', 'Cache-Control': 'no-cache' }); r.type('application/javascript'); r.sendFile(path.join(__dirname, 'sw.js')); });

// ---- Admin ----
const tries = {};
app.post('/api/login', (q, r) => {
  const t = tries[q.ip] = (tries[q.ip] || []).filter(x => Date.now() - x < 15 * 60e3);
  if (t.length >= 8) return r.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const pw = String(q.body.password || '');
  if (!same(sign(pw), sign(E.ADMIN_PASSWORD))) { t.push(Date.now()); return r.status(401).json({ error: 'Wrong password' }); }
  r.cookie('s', sign('admin'), { httpOnly: true, sameSite: 'strict', secure: q.secure, maxAge: 7 * 24 * 3600e3 });
  r.json({ ok: true });
});
app.post('/api/logout', (q, r) => { r.clearCookie('s'); r.json({ ok: true }); });
app.get('/api/me', (q, r) => r.json({ admin: isAdmin(q) }));

async function buildSchedule(s) {
  const ids = (Array.isArray(s.vehicleIds) ? s.vehicleIds : (s.vehicleId ? [s.vehicleId] : [])).map(num).filter(Boolean).slice(0, 10);
  const items = [];
  for (const id of ids) {
    const v = await one('select id,name,rego,daily_rate,bond,excess,image,type from vehicles where id=$1', [id]);
    if (v) items.push({ vehicleId: v.id, name: v.name, type: v.type || 'Car', rego: v.rego || '', image: v.image || null, dailyRate: v.daily_rate || '', bond: v.bond || '', excess: v.excess || '' });
  }
  if (!items.length) {
    const name = String(s.vehicle || '').trim();
    if (!name) return null;
    items.push({ vehicleId: null, name, type: s.mode === 'Jet ski' ? 'Jet ski' : 'Car', rego: String(s.rego || ''), image: null });
  }
  s.items = items; s.vehicle = items.map(i => i.name).join(' + ');
  s.vehicleId = items[0].vehicleId; s.carImage = items[0].image; s.itemType = items[0].type;
  s.hasCar = items.some(i => i.type !== 'Jet ski'); s.hasJet = items.some(i => i.type === 'Jet ski');
  return s;
}
app.put('/api/bookings/:id', auth, A(async (q, r) => {
  const id = num(q.params.id), b = await one('select status from bookings where id=$1', [id]);
  if (!b) return r.status(404).json({ error: 'Not found' });
  if (b.status !== 'pending') return r.status(409).json({ error: 'Only bookings that are not yet signed can be edited. Cancel it and create a new one instead.' });
  const s = await buildSchedule(q.body || {});
  if (!s) return r.status(400).json({ error: 'Vehicle name is required' });
  delete s.linkDays; delete s.prefillFrom;
  await pool.query('update bookings set vehicle=$1, schedule=$2 where id=$3', [s.vehicle, JSON.stringify(s), id]);
  r.json({ ok: true });
}));
app.post('/api/bookings/:id/cancel', auth, A(async (q, r) => {
  await pool.query("update bookings set status='cancelled', cancelled_at=$1, cancel_note=$2 where id=$3 and status<>'cancelled'", [new Date().toISOString(), String((q.body || {}).note || '').slice(0, 500), num(q.params.id)]);
  r.json({ ok: true });
}));
app.post('/api/bookings/:id/reinstate', auth, A(async (q, r) => {
  await pool.query("update bookings set status=case when signed_at is null then 'pending' else 'signed' end, cancelled_at=null, cancel_note=null where id=$1 and status='cancelled'", [num(q.params.id)]);
  r.json({ ok: true });
}));
app.put('/api/bookings/:id/charges', auth, A(async (q, r) => {
  const list = (Array.isArray(q.body) ? q.body : []).slice(0, 50).map(c => ({ date: String(c.date || '').slice(0, 20), type: ['Fine', 'Toll', 'Other'].includes(c.type) ? c.type : 'Other', amount: String(c.amount || '').slice(0, 20), note: String(c.note || '').slice(0, 300), recovered: !!c.recovered }));
  await pool.query('update bookings set charges=$1 where id=$2', [JSON.stringify(list), num(q.params.id)]);
  r.json({ ok: true });
}));
app.post('/api/bookings/:id/email-copy', auth, A(async (q, r) => {
  if (!mail) return r.status(400).json({ error: 'Email is not set up yet. Add the SMTP settings in Render (see README).' });
  const b = await one('select customer from bookings where id=$1', [num(q.params.id)]);
  if (!b || !b.customer) return r.status(400).json({ error: 'This booking has not been signed yet.' });
  try { await sendCopy(num(q.params.id), JSON.parse(b.customer).email); r.json({ ok: true }); }
  catch (e) { console.error('Email failed:', e.message); r.status(500).json({ error: 'Email failed: ' + e.message }); }
}));
const csvCell = v => { let s = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
app.get('/export/bookings.csv', auth, A(async (q, r) => {
  const rows = await all('select * from bookings order by id');
  const head = ['ID', 'Created', 'Status', 'Vehicle', 'Type', 'Registration', 'Pickup', 'Return', 'Daily rate', 'Total price', 'Deposit', 'Bond', 'Customer', 'Date of birth', 'Mobile', 'Email', 'Address', 'Licence no', 'Licence expiry', 'Signed at', 'Rental paid', 'Deposit paid', 'Bond received', 'Bond refunded', 'Refund date', 'Fines/tolls total', 'Cancelled at', 'Cancel note'];
  const out = [head.map(csvCell).join(',')];
  for (const b of rows) {
    const s = JSON.parse(b.schedule), c = b.customer ? JSON.parse(b.customer) : {}, t = b.tracker ? JSON.parse(b.tracker) : {}, ch = b.charges ? JSON.parse(b.charges) : [];
    const yn = v => v ? 'Yes' : 'No';
    out.push([b.id, b.created, b.status, b.vehicle, itemsOf(s).map(i => i.type).join(' + '), s.rego, String(s.pickup || '').replace('T', ' '), String(s.ret || '').replace('T', ' '), s.dailyRate, s.totalPrice, s.deposit, s.bond, c.name, c.dob, c.mobile, c.email, c.address, c.licenceNo || c.marineNo, c.licenceExpiry || c.marineExpiry, b.signed_at, yn(t.rentalPaid), yn(t.depositPaid), yn(t.bondPaid), yn(t.bondRefunded), t.refundDate, ch.reduce((a, x) => a + (+x.amount || 0), 0).toFixed(2), b.cancelled_at, b.cancel_note].map(csvCell).join(','));
  }
  r.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="rpm-bookings.csv"' });
  r.send('\ufeff' + out.join('\r\n'));
}));

app.post('/api/bookings', auth, A(async (q, r) => {
  const s = await buildSchedule(q.body || {});
  if (!s) return r.status(400).json({ error: 'Vehicle name is required' });
  const ld = s.linkDays === undefined || s.linkDays === '' ? 7 : num(s.linkDays), days = [0, 1, 3, 7, 14, 30].includes(ld) ? ld : 7;
  const src = num(s.prefillFrom), reqId = num(s.requestId); delete s.linkDays; delete s.prefillFrom; delete s.requestId;
  let prefill = null;
  if (src) {
    const p = await one('select schedule,customer,id_file,id_back,id_app from bookings where id=$1 and customer is not null', [src]);
    if (p) {
      const c = JSON.parse(p.customer), ps = JSON.parse(p.schedule), srcCar = ps.hasCar !== false, fields = {};
      for (const k of ['name', 'dob', 'address', 'mobile', 'email', 'emergency', 'licenceNo', 'licenceState', 'licenceExpiry', 'pPlate', 'marineNo', 'marineState', 'marineExpiry']) if (c[k]) fields[k] = c[k];
      prefill = JSON.stringify({ fields, files: { front: srcCar ? p.id_file : null, back: srcCar ? p.id_back : null, app: srcCar ? p.id_app : null,
        marineFront: c.marineFiles ? c.marineFiles.front : (srcCar ? null : p.id_file), marineBack: c.marineFiles ? c.marineFiles.back : (srcCar ? null : p.id_back) } });
    }
  }
  if (reqId) {
    const rq = await one('select name,mobile,email from requests where id=$1', [reqId]);
    if (rq) { const p = prefill ? JSON.parse(prefill) : { fields: {}, files: {} }; for (const k of ['name', 'mobile', 'email']) if (!p.fields[k] && rq[k]) p.fields[k] = rq[k]; prefill = JSON.stringify(p); }
  }
  const token = crypto.randomBytes(24).toString('base64url');
  const row = await one('insert into bookings(token,created,vehicle,schedule,link_expires,prefill) values($1,$2,$3,$4,$5,$6) returning id',
    [token, new Date().toISOString(), s.vehicle, JSON.stringify(s), days ? new Date(Date.now() + days * 864e5).toISOString() : null, prefill]);
  if (reqId) await pool.query("update requests set status='approved', booking_id=$1 where id=$2", [row.id, reqId]);
  r.json({ id: row.id, link: (E.BASE_URL || q.protocol + '://' + q.get('host')) + '/s/' + token });
}));
app.get('/api/bookings', auth, A(async (q, r) => r.json((await all(
  `select id,token,created,status,vehicle,schedule,customer,signed_at,tracker,charges,cancelled_at,cancel_note,link_expires,
    exists(select 1 from condition_reports c where c.booking_id=bookings.id and c.stage='return') as returned,
    exists(select 1 from condition_reports c where c.booking_id=bookings.id and c.stage='handover') as handed
    from bookings order by id desc`))
  .map(b => ({ ...b, schedule: JSON.parse(b.schedule), customer: b.customer && JSON.parse(b.customer), tracker: b.tracker ? JSON.parse(b.tracker) : {}, charges: b.charges ? JSON.parse(b.charges) : [] })))));
app.get('/api/bookings/:id', auth, A(async (q, r) => {
  const b = await one('select * from bookings where id=$1', [num(q.params.id)]);
  if (!b) return r.status(404).json({ error: 'Not found' });
  const condition = await all('select stage,reading,fuel,notes,photos,created from condition_reports where booking_id=$1', [b.id]);
  r.json({ ...b, schedule: JSON.parse(b.schedule), customer: b.customer && JSON.parse(b.customer), tracker: b.tracker ? JSON.parse(b.tracker) : {}, charges: b.charges ? JSON.parse(b.charges) : [], condition });
}));
app.get('/api/bookings/:id/photo/:which', auth, A(async (q, r) => {
  const col = { front: 'id_file', back: 'id_back', app: 'id_app' }[q.params.which];
  const b = col && await one('select ' + col + ' as f from bookings where id=$1', [num(q.params.id)]);
  await sendFile(b && b.f, r);
}));


app.get('/api/customers', auth, A(async (q, r) => {
  const term = String(q.query.q || '').toLowerCase().trim();
  if (term.length < 2) return r.json([]);
  const rows = await all('select id,customer from bookings where customer is not null order by id desc limit 500');
  const seen = new Set(), out = [];
  for (const b of rows) {
    const c = JSON.parse(b.customer), key = (c.email || c.mobile || c.name || '').toLowerCase();
    if (seen.has(key) || !((c.name || '') + ' ' + (c.mobile || '') + ' ' + (c.email || '')).toLowerCase().includes(term)) continue;
    seen.add(key); out.push({ bookingId: b.id, name: c.name, mobile: c.mobile, email: c.email });
    if (out.length >= 8) break;
  }
  r.json(out);
}));
app.post('/api/bookings/:id/extend', auth, A(async (q, r) => {
  const d = num((q.body || {}).days) || 7;
  await pool.query("update bookings set link_expires=$1 where id=$2 and status='pending'", [new Date(Date.now() + d * 864e5).toISOString(), num(q.params.id)]);
  r.json({ ok: true });
}));
// ---- Push notifications ----
async function initPush() {
  let row = await one("select value from settings where key='vapid'");
  if (!row) { await pool.query("insert into settings(key,value) values('vapid',$1) on conflict (key) do nothing", [JSON.stringify(webpush.generateVAPIDKeys())]); row = await one("select value from settings where key='vapid'"); }
  const k = JSON.parse(row.value);
  webpush.setVapidDetails(E.PUSH_CONTACT || 'mailto:' + (E.NOTIFY_EMAIL || 'admin@example.com'), k.publicKey, k.privateKey);
}
async function notifyPush(p) {
  const subs = await all('select endpoint,data from push_subs'); let sent = 0; const errors = [];
  for (const s of subs) {
    try { await webpush.sendNotification(JSON.parse(s.data), JSON.stringify(p)); sent++; }
    catch (e) {
      const why = (e.statusCode || '') + ' ' + String(e.body || e.message || '').slice(0, 120);
      console.error('Push failed:', why); errors.push(why.trim());
      if (e.statusCode === 404 || e.statusCode === 410) await pool.query('delete from push_subs where endpoint=$1', [s.endpoint]);
    }
  }
  return { total: subs.length, sent, errors };
}
app.get('/api/push/key', auth, A(async (q, r) => { const row = await one("select value from settings where key='vapid'"); r.json({ key: JSON.parse(row.value).publicKey }); }));
app.post('/api/push/subscribe', auth, A(async (q, r) => {
  const s = q.body || {};
  if (!s.endpoint) return r.status(400).json({ error: 'Bad subscription' });
  await pool.query('insert into push_subs(endpoint,data,created) values($1,$2,$3) on conflict (endpoint) do update set data=$2', [s.endpoint, JSON.stringify(s), new Date().toISOString()]);
  r.json({ ok: true });
}));
app.post('/api/push/unsubscribe', auth, A(async (q, r) => { await pool.query('delete from push_subs where endpoint=$1', [String((q.body || {}).endpoint || '')]); r.json({ ok: true }); }));
app.post('/api/push/test', auth, A(async (q, r) => r.json({ ok: true, ...(await notifyPush({ title: 'RPM Rentals', body: 'Test notification - it works!', url: '/admin' })) })));
// ---- Payments, condition reports ----
app.put('/api/bookings/:id/tracker', auth, A(async (q, r) => {
  const t = q.body || {};
  const clean = { rentalPaid: !!t.rentalPaid, depositPaid: !!t.depositPaid, bondPaid: !!t.bondPaid, bondRefunded: !!t.bondRefunded, refundDate: String(t.refundDate || '').slice(0, 20), notes: String(t.notes || '').slice(0, 1000) };
  await pool.query('update bookings set tracker=$1 where id=$2', [JSON.stringify(clean), num(q.params.id)]);
  r.json({ ok: true });
}));
app.post('/api/bookings/:id/condition', auth, upload.array('photos', 12), A(async (q, r) => {
  const id = num(q.params.id), stage = q.body.stage === 'return' ? 'return' : 'handover';
  const names = []; for (const f of (q.files || [])) names.push(await saveFile(f));
  const fields = [String(q.body.reading || '').slice(0, 100), String(q.body.fuel || '').slice(0, 100), String(q.body.notes || '').slice(0, 2000)];
  const ex = await one('select id,photos from condition_reports where booking_id=$1 and stage=$2', [id, stage]);
  if (ex) await pool.query('update condition_reports set reading=$1,fuel=$2,notes=$3,photos=$4,created=$5 where id=$6', [...fields, JSON.stringify(JSON.parse(ex.photos || '[]').concat(names)), new Date().toISOString(), ex.id]);
  else await pool.query('insert into condition_reports(booking_id,stage,reading,fuel,notes,photos,created) values($1,$2,$3,$4,$5,$6,$7)', [id, stage, ...fields, JSON.stringify(names), new Date().toISOString()]);
  r.json({ ok: true });
}));
app.get('/api/file/:name', auth, A(async (q, r) => sendFile(q.params.name, r)));

// ---- Signed record (print / save as PDF) ----
const LBL = { vehicle: 'Vehicle', rego: 'Registration', pickup: 'Pickup', ret: 'Return', dailyRate: 'Daily rate $', totalPrice: 'Total price $', deposit: 'Booking deposit $', bond: 'Security bond $', includedKm: 'Included km', excessKmRate: 'Excess km rate', excess: 'Insurance excess $', youngExcess: 'Young driver excess $', holdAmount: 'Second driving event hold $', pickupLoc: 'Pickup location', retLoc: 'Return location', hin: 'Hull ID', engineHours: 'Engine hours at handover', lateFee: 'Late return fee $', extras: 'Additional charges', equipment: 'Equipment supplied', fuel: 'Fuel on handover', towing: 'Towing authorised', dashcamAudio: 'Dashcam audio', notes: 'Notes' };
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
app.get('/record/:id', auth, A(async (q, r) => {
  const b = await one('select * from bookings where id=$1', [num(q.params.id)]);
  if (!b || !b.signed_at) return r.status(404).send('Not found');
  const s = JSON.parse(b.schedule), c = JSON.parse(b.customer);
  const dl = rows => '<dl>' + rows.filter(([k, v]) => v != null && v !== '').map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>';
  const sched = Object.keys(LBL).filter(k => s[k]).map(k => [LBL[k], k === 'pickup' || k === 'ret' ? String(s[k]).replace('T', ' ') : s[k]]);
  const when = new Date(b.signed_at).toLocaleString('en-AU', { dateStyle: 'long', timeStyle: 'short', timeZone: 'Australia/Melbourne' });
  const cond = await all('select stage,reading,fuel,notes,photos from condition_reports where booking_id=$1 order by stage desc', [b.id]);
  const condHtml = cond.map(c => '<h3>' + (c.stage === 'return' ? 'Return' : 'Handover') + ' condition</h3>' + dl([['Odometer / engine hours', c.reading], ['Fuel', c.fuel], ['Notes', c.notes]]) + '<div class="ph">' + JSON.parse(c.photos || '[]').map(n => '<figure><img src="/api/file/' + esc(n) + '"></figure>').join('') + '</div>').join('');
  const photo = w => '<figure><img src="/api/bookings/' + b.id + '/photo/' + w + '"><figcaption>' + w + '</figcaption></figure>';
  r.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Signed agreement - ${esc(c.name)}</title><style>
body{font:14px/1.5 system-ui,sans-serif;color:#1b2230;max-width:820px;margin:0 auto;padding:20px}
.brand{background:#000;text-align:center;border-radius:10px;padding:6px}.brand img{height:110px}
h1{font-size:20px;margin:16px 0 4px}h2{font-size:15px;margin:20px 0 6px;border-bottom:1px solid #ccd;padding-bottom:3px}
dl{display:grid;grid-template-columns:200px 1fr;gap:3px 12px;margin:0}dt{color:#667085}dd{margin:0}
.ph{display:flex;gap:10px;flex-wrap:wrap}.ph figure{margin:0;flex:1 1 200px}.ph img{width:100%;border:1px solid #ccd;border-radius:6px}figcaption{font-size:12px;color:#667085}
pre{white-space:pre-wrap;font:12px/1.45 system-ui,sans-serif}.agr{page-break-before:always}
button{padding:10px 18px;border:0;border-radius:8px;background:#0b6e5c;color:#fff;font-weight:700;cursor:pointer;margin:12px 0}
@media print{.noprint{display:none}}</style></head><body>
<div class="brand"><img src="/logo.jpg" alt="RPM Rental Group"></div>
<button class="noprint" onclick="print()">Save as PDF / Print</button>
<h1>Signed rental agreement</h1><p>Signed by <b>${esc(c.name)}</b> on ${esc(when)}</p>
<p>${itemsOf(s).map((x, i) => x.image ? '<img src="/car/' + esc(b.token) + '/' + i + '" style="max-width:240px;border-radius:8px;margin:0 8px 8px 0">' : '').join('')}</p>
<h2>Rental schedule</h2>${dl(sched)}
<h2>Hirer details</h2>${dl([['Name', c.name], ['Date of birth', c.dob], ['Address', c.address], ['Mobile', c.mobile], ['Email', c.email], ['Emergency contact', c.emergency], ['Licence number', c.licenceNo], ['Licence state / class', c.licenceState], ['Licence expiry', c.licenceExpiry], ['Licence type', c.pPlate], ['Marine licence number', c.marineNo], ['Marine endorsement', c.marineState], ['Marine licence expiry', c.marineExpiry]])}
<h2>Signature</h2><img src="${esc(b.signature)}" style="max-width:320px;border:1px solid #ccd;border-radius:6px">
<h2>Signing record</h2>${dl([['Signed', when], ['IP address', b.ip], ['Device', b.ua], ['Agreement version (SHA-256)', b.agreement_hash]])}
<h2>Licence photos</h2><div class="ph">${photo('front')}${photo('back')}${b.id_app ? photo('app') : ''}${c.marineFiles && s.hasCar ? '<figure><img src="/api/file/' + esc(c.marineFiles.front) + '"><figcaption>marine front</figcaption></figure><figure><img src="/api/file/' + esc(c.marineFiles.back) + '"><figcaption>marine back</figcaption></figure>' : ''}</div>
<h2>Condition reports</h2>${condHtml || "<p>None recorded.</p>"}
<div class="agr"><h2>Agreement terms accepted</h2><pre>${esc(b.agreement_text)}</pre></div>
</body></html>`);
}));

// ---- Email copy to customer ----
const logoData = (() => { try { return 'data:image/jpeg;base64,' + fs.readFileSync(path.join(__dirname, 'logo.jpg')).toString('base64'); } catch (e) { return ''; } })();
function copyHtml(b) {
  const s = JSON.parse(b.schedule), c = JSON.parse(b.customer);
  const tbl = rows => '<table style="border-collapse:collapse">' + rows.map(([k, v]) => '<tr><td style="padding:2px 14px 2px 0;color:#667085">' + esc(k) + '</td><td>' + esc(v) + '</td></tr>').join('') + '</table>';
  const sched = Object.keys(LBL).filter(k => s[k]).map(k => [LBL[k], k === 'pickup' || k === 'ret' ? String(s[k]).replace('T', ' ') : s[k]]);
  const when = new Date(b.signed_at).toLocaleString('en-AU', { dateStyle: 'long', timeStyle: 'short', timeZone: 'Australia/Melbourne' });
  return '<!doctype html><html><head><meta charset="utf-8"><title>Signed agreement</title></head><body style="font-family:system-ui,sans-serif;color:#1b2230;max-width:760px;margin:0 auto;padding:20px">'
    + (logoData ? '<div style="background:#000;text-align:center;padding:6px;border-radius:10px"><img src="' + logoData + '" style="height:100px"></div>' : '')
    + '<h2>Signed rental agreement - RPM Rental Group Pty Ltd</h2><p>Signed by ' + esc(c.name) + ' on ' + esc(when) + '</p><h3>Rental details</h3>' + tbl(sched)
    + '<h3>Hirer</h3>' + tbl([['Name', c.name], ['Mobile', c.mobile], ['Email', c.email]])
    + '<h3>Signature</h3><img src="' + esc(b.signature) + '" style="max-width:300px;border:1px solid #ccd">'
    + '<h3>Agreement terms</h3><pre style="white-space:pre-wrap;font:12px/1.45 system-ui,sans-serif">' + esc(b.agreement_text) + '</pre>'
    + '<p style="color:#667085;font-size:12px">Agreement version (SHA-256): ' + esc(b.agreement_hash) + '</p></body></html>';
}
async function sendCopy(id, to) {
  if (!mail || !to) return false;
  const b = await one('select * from bookings where id=$1', [id]);
  if (!b || !b.signed_at) return false;
  const c = JSON.parse(b.customer);
  await mail.sendMail({ from: E.SMTP_FROM || E.SMTP_USER, to, subject: 'Your signed rental agreement - RPM Rental Group',
    text: 'Hi ' + c.name + ',\n\nThank you for signing your rental agreement with RPM Rental Group for ' + b.vehicle + '. A copy is attached. Please keep it for your records.\n\nRPM Rental Group',
    attachments: [{ filename: 'Signed-agreement.html', content: copyHtml(b), contentType: 'text/html' }] });
  return true;
}

// ---- Public website ----
const hits = {};
const limited = (key, max, ms) => { const now = Date.now(), a = hits[key] = (hits[key] || []).filter(t => now - t < ms); if (a.length >= max) return true; a.push(now); return false; };
const okDate = v => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(String(v || ''));
async function isFree(vehicleId, from, to) {
  const rows = await all("select schedule from bookings where status<>'cancelled'");
  for (const b of rows) {
    const s = JSON.parse(b.schedule); if (!s.pickup || !s.ret) continue;
    const ids = (s.items || []).map(i => String(i.vehicleId)).concat(s.vehicleId ? [String(s.vehicleId)] : []);
    if (ids.includes(String(vehicleId)) && s.pickup < to && s.ret > from) return false;
  }
  return true;
}
app.get('/api/public/fleet', A(async (q, r) => r.json((await all("select id,name,type,daily_rate,image from vehicles where coalesce(listed,'yes')<>'no' order by name"))
  .map(v => ({ id: v.id, name: v.name, type: v.type || 'Car', rate: v.daily_rate || '', hasImage: !!v.image })))));
app.get('/api/public/info', (q, r) => r.json({ phone: E.PUBLIC_PHONE || '', email: E.PUBLIC_EMAIL || '' }));
app.get('/vimg/:id', A(async (q, r) => { const v = await one("select image from vehicles where id=$1 and coalesce(listed,'yes')<>'no'", [num(q.params.id)]); await sendFile(v && v.image, r); }));
app.get('/api/public/availability', A(async (q, r) => {
  if (limited('av:' + q.ip, 90, 60e3)) return r.status(429).json({ ok: false });
  const id = num(q.query.vehicleId), from = String(q.query.from || ''), to = String(q.query.to || '');
  if (!id || !okDate(from) || !okDate(to) || from >= to) return r.json({ ok: false });
  r.json({ ok: true, free: await isFree(id, from, to) });
}));
app.post('/api/public/request', A(async (q, r) => {
  const b = q.body || {};
  if (b.website) return r.json({ ok: true });
  if (limited('rq:' + q.ip, 6, 3600e3)) return r.status(429).json({ error: 'Too many requests. Please try again later or contact us directly.' });
  const id = num(b.vehicleId), from = String(b.pickup || ''), to = String(b.ret || '');
  const name = String(b.name || '').trim().slice(0, 100), mobile = String(b.mobile || '').trim().slice(0, 30), email = String(b.email || '').trim().slice(0, 120), notes = String(b.notes || '').trim().slice(0, 600);
  if (!name || !/^[0-9+()\s-]{8,}$/.test(mobile) || !/^\S+@\S+\.\S+$/.test(email)) return r.status(400).json({ error: 'Please check your name, mobile number and email.' });
  if (!okDate(from) || !okDate(to) || from >= to) return r.status(400).json({ error: 'Please choose valid pickup and return times.' });
  if (from.slice(0, 10) < new Date().toLocaleDateString('en-CA', { timeZone: 'Australia/Melbourne' })) return r.status(400).json({ error: 'The pickup date cannot be in the past.' });
  const v = await one("select id,name from vehicles where id=$1 and coalesce(listed,'yes')<>'no'", [id]);
  if (!v) return r.status(400).json({ error: 'That vehicle is not available to book online.' });
  if (!(await isFree(id, from, to))) return r.status(409).json({ error: 'Sorry, that vehicle is already booked for those dates. Please try other dates.' });
  await pool.query('insert into requests(created,vehicle_id,vehicle_name,pickup,ret,name,mobile,email,notes,ip) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [new Date().toISOString(), v.id, v.name, from, to, name, mobile, email, notes, q.ip]);
  const when = from.replace('T', ' ') + ' to ' + to.replace('T', ' ');
  notifyPush({ title: 'New booking request', body: name + ' - ' + v.name + ' (' + when + ')', url: '/admin#req' }).catch(e => console.error('Push failed:', e.message));
  if (mail) {
    const fromAddr = E.SMTP_FROM || E.SMTP_USER;
    if (E.NOTIFY_EMAIL) mail.sendMail({ from: fromAddr, to: E.NOTIFY_EMAIL, subject: 'New booking request: ' + v.name, text: name + '\n' + mobile + '\n' + email + '\n' + v.name + '\n' + when + (notes ? '\n\n' + notes : '') + '\n\nOpen your admin app, Requests tab, to respond.' }).catch(e => console.error('Email failed:', e.message));
    mail.sendMail({ from: fromAddr, to: email, subject: 'We received your booking request - RPM Rental Group', text: 'Hi ' + name + ',\n\nThanks for your request for the ' + v.name + ' (' + when + '). This is not a confirmed booking yet. We will contact you shortly to confirm the details, the deposit and the security bond, and send you a link to sign your rental agreement.\n\nRPM Rental Group' }).catch(e => console.error('Customer email failed:', e.message));
  }
  r.json({ ok: true });
}));
app.get('/api/requests', auth, A(async (q, r) => r.json(await all('select * from requests order by id desc limit 200'))));
app.post('/api/requests/:id/decline', auth, A(async (q, r) => { await pool.query("update requests set status='declined' where id=$1 and status='new'", [num(q.params.id)]); r.json({ ok: true }); }));
app.put('/api/vehicles/:id/listed', auth, A(async (q, r) => { await pool.query('update vehicles set listed=$1 where id=$2', [(q.body || {}).listed ? 'yes' : 'no', num(q.params.id)]); r.json({ ok: true }); }));

// ---- Fleet ----
app.get('/api/vehicles', auth, A(async (q, r) => r.json(await all('select id,name,rego,daily_rate,bond,excess,image,type,listed from vehicles order by name'))));
app.post('/api/vehicles', auth, upload.single('image'), A(async (q, r) => {
  const b = q.body || {}, name = String(b.name || '').trim();
  if (!name) return r.status(400).json({ error: 'Name is required' });
  const type = ['Car', 'Jet ski', 'Other'].includes(b.type) ? b.type : 'Car';
  const img = q.file ? await saveFile(q.file) : null;
  await pool.query('insert into vehicles(name,rego,daily_rate,bond,excess,image,created,type) values($1,$2,$3,$4,$5,$6,$7,$8)',
    [name, String(b.rego || '').trim(), String(b.dailyRate || ''), String(b.bond || ''), String(b.excess || ''), img, new Date().toISOString(), type]);
  r.json({ ok: true });
}));
app.get('/api/vehicles/:id/image', auth, A(async (q, r) => { const v = await one('select image from vehicles where id=$1', [num(q.params.id)]); await sendFile(v && v.image, r); }));
app.delete('/api/vehicles/:id', auth, A(async (q, r) => { await pool.query('delete from vehicles where id=$1', [num(q.params.id)]); r.json({ ok: true }); }));
app.get('/car/:token/:n?', A(async (q, r) => {
  const b = await one('select schedule from bookings where token=$1', [q.params.token]);
  const it = b ? itemsOf(JSON.parse(b.schedule)) : [];
  await sendFile((it[num(q.params.n)] || {}).image, r);
}));

// ---- Customer (private link) ----
const expired = b => b.status === 'pending' && b.link_expires && new Date(b.link_expires) < new Date();
const baseNeed = ['name', 'dob', 'address', 'mobile', 'email', 'emergency'];
app.get('/api/c/:token', A(async (q, r) => {
  const b = await one('select status,schedule,link_expires,prefill from bookings where token=$1', [q.params.token]);
  if (!b) return r.status(404).json({ error: 'This link is not valid.' });
  if (b.status === 'cancelled') return r.status(410).json({ error: 'This booking has been cancelled.' });
  if (b.status === 'signed') return r.json({ signed: true });
  if (expired(b)) return r.status(410).json({ error: 'This link has expired.' });
  const sch = JSON.parse(b.schedule), ag = agreementFor(sch), items = itemsOf(sch);
  const pf = b.prefill ? JSON.parse(b.prefill) : null, pfl = (pf && pf.files) || {};
  r.json({ signed: false, agreement: ag.text, prefill: pf ? pf.fields : null,
    onFile: { driver: !!(pfl.front && pfl.back), marine: !!(pfl.marineFront && pfl.marineBack) },
    schedule: { ...sch, carImage: null, items: items.map((i, n) => ({ name: i.name, type: i.type, rego: i.rego || '', excess: i.excess || '', hasImage: !!i.image, n })) } });
}));
app.post('/api/c/:token', upload.fields([{ name: 'idFront', maxCount: 1 }, { name: 'idBack', maxCount: 1 }, { name: 'idApp', maxCount: 1 }, { name: 'marineFront', maxCount: 1 }, { name: 'marineBack', maxCount: 1 }]), A(async (q, r) => {
  const b = await one('select id,status,vehicle,schedule,link_expires,prefill from bookings where token=$1', [q.params.token]);
  const fail = (c, m) => r.status(c).json({ error: m });
  if (!b) return fail(404, 'This link is not valid.');
  if (b.status === 'cancelled') return fail(410, 'This booking has been cancelled.');
  if (b.status === 'signed') return fail(409, 'This agreement has already been signed.');
  if (expired(b)) return fail(410, 'This link has expired.');
  const sch = JSON.parse(b.schedule), it = itemsOf(sch), hasCar = it.some(i => i.type !== 'Jet ski'), hasJet = it.some(i => i.type === 'Jet ski');
  const need = baseNeed.concat(hasCar ? ['licenceNo', 'licenceState', 'licenceExpiry', 'pPlate'] : [], hasJet ? ['marineNo', 'marineState', 'marineExpiry'] : []);
  const c = {}; for (const k of need) { c[k] = String(q.body[k] || '').trim().slice(0, 300); if (!c[k]) return fail(400, 'Please fill in all fields.'); }
  const P = q.files || {}, pfl = (b.prefill ? JSON.parse(b.prefill).files : null) || {};
  if (hasCar && !((P.idFront || pfl.front) && (P.idBack || pfl.back))) return fail(400, 'Please upload the front and back of your driver licence.');
  if (hasJet && !((P.marineFront || pfl.marineFront) && (P.marineBack || pfl.marineBack))) return fail(400, 'Please upload the front and back of your marine licence.');
  if (q.body.agreed !== 'true') return fail(400, 'You must confirm you have read the agreement.');
  const sig = String(q.body.signature || '');
  if (!/^data:image\/png;base64,/.test(sig) || sig.length > 400000) return fail(400, 'Please sign in the signature box.');
  const ag = agreementFor(sch), fresh = [];
  const save = async k => { if (!P[k]) return null; const n = await saveFile(P[k][0]); fresh.push(n); return n; };
  const n = { idFront: await save('idFront'), idBack: await save('idBack'), idApp: await save('idApp'), marineFront: await save('marineFront'), marineBack: await save('marineBack') };
  if (hasCar) { n.idFront = n.idFront || pfl.front || null; n.idBack = n.idBack || pfl.back || null; n.idApp = n.idApp || pfl.app || null; }
  if (hasJet) { n.marineFront = n.marineFront || pfl.marineFront || null; n.marineBack = n.marineBack || pfl.marineBack || null; c.marineFiles = { front: n.marineFront, back: n.marineBack }; }
  const f1 = hasCar ? n.idFront : n.marineFront, f2 = hasCar ? n.idBack : n.marineBack;
  const done = await pool.query(`update bookings set status='signed',customer=$1,id_file=$2,id_back=$3,id_app=$4,signature=$5,signed_at=$6,ip=$7,ua=$8,agreement_hash=$9,agreement_text=$10
    where id=$11 and status='pending'`, [JSON.stringify(c), f1, f2, hasCar ? n.idApp : null, sig, new Date().toISOString(), q.ip,
    String(q.get('user-agent') || '').slice(0, 300), ag.hash, ag.text, b.id]);
  if (!done.rowCount) { if (fresh.length) await pool.query('delete from files where name = any($1)', [fresh]); return fail(409, 'This agreement has already been signed.'); }
  if (mail && E.NOTIFY_EMAIL) mail.sendMail({ from: E.SMTP_USER, to: E.NOTIFY_EMAIL,
    subject: `Signed: ${c.name} - ${b.vehicle}`,
    text: `${c.name} signed the rental agreement for ${b.vehicle}.\nMobile: ${c.mobile}\nOpen your dashboard to view the details and licence photos.` })
    .catch(e => console.error('Email failed:', e.message));
  sendCopy(b.id, c.email).catch(e => console.error('Customer email failed:', e.message));
  notifyPush({ title: 'Agreement signed', body: c.name + ' signed for ' + b.vehicle, url: '/admin#hist' }).catch(e => console.error('Push failed:', e.message));
  r.json({ ok: true });
}));

ready.then(initPush).then(() => app.listen(E.PORT || 3000, () => console.log('Running on port ' + (E.PORT || 3000))))
  .catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
