// ねむ リンクサイト管理ページ用 認証バックエンド
// MyBoard (board.parumenn.com) の認証方式に倣った単一管理者向け実装:
//  - パスワードログイン（ハッシュは k8s Secret の環境変数で受け取る）
//  - パスキー (WebAuthn) 登録/ログイン（ユーザーネームレス、RP ID = parumenn.com）
//  - サーバ側セッション（トークン本体は Cookie のみ、保存は HMAC ハッシュ）
//  - Cookie: __Host-linkadmin / HttpOnly / Secure / SameSite=Lax、絶対期限30日・アイドル7日
//  - パスキー追加/削除には再認証 (step-up, 5分) を要求
// 依存パッケージなし (Node 標準ライブラリのみ)。状態は DATA_DIR/state.json に永続化。
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const PORT = Number(process.env.PORT || 8080);
const RP_ID = process.env.RP_ID || 'parumenn.com';
const RP_NAME = process.env.RP_NAME || 'ねむ管理ページ';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://go.parumenn.com')
  .split(',').map(s => s.trim()).filter(Boolean);
const PASSWORD_HASH = process.env.LINK_ADMIN_PASSWORD_HASH || '';
const AUTH_SECRET = process.env.AUTH_SECRET || '';
const DATA_DIR = process.env.DATA_DIR || '/data';
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const COOKIE_NAME = '__Host-nemuadmin';
const SESSION_TTL_MS = 30 * 24 * 3600 * 1000;
const SESSION_IDLE_MS = 7 * 24 * 3600 * 1000;
const STEP_UP_WINDOW_MS = 5 * 60 * 1000;
const CHALLENGE_TTL_MS = 10 * 60 * 1000;
const ADMIN_USER_ID = Buffer.from('link-admin', 'utf8');
const ADMIN_USER_NAME = 'admin-nemu@go.parumenn.com';

// ---------- small helpers ----------
const b64url = buf => Buffer.from(buf).toString('base64url');
const b64urlDecode = s => Buffer.from(String(s), 'base64url');
const sha256 = buf => crypto.createHash('sha256').update(buf).digest();
const randomToken = (bytes = 32) => b64url(crypto.randomBytes(bytes));
const nowIso = () => new Date().toISOString();

function tokenHash(token) {
  return crypto.createHmac('sha256', AUTH_SECRET || 'insecure-dev-secret')
    .update(token).digest('hex');
}

// ---------- minimal CBOR decoder (WebAuthn で必要な型のみ) ----------
function cborDecode(buf, offset = 0) {
  const first = buf[offset];
  const major = first >> 5;
  const ai = first & 0x1f;
  let pos = offset + 1;
  let arg;
  if (ai < 24) arg = ai;
  else if (ai === 24) { arg = buf[pos]; pos += 1; }
  else if (ai === 25) { arg = buf.readUInt16BE(pos); pos += 2; }
  else if (ai === 26) { arg = buf.readUInt32BE(pos); pos += 4; }
  else if (ai === 27) { arg = Number(buf.readBigUInt64BE(pos)); pos += 8; }
  else if (ai === 31) arg = -1; // indefinite (map/array の break は呼び出し側で処理)
  else throw new Error('cbor: unsupported additional info');
  switch (major) {
    case 0: return { value: arg, next: pos };
    case 1: return { value: -1 - arg, next: pos };
    case 2: return { value: buf.subarray(pos, pos + arg), next: pos + arg };
    case 3: return { value: buf.subarray(pos, pos + arg).toString('utf8'), next: pos + arg };
    case 4: {
      const arr = [];
      if (arg === -1) {
        while (buf[pos] !== 0xff) { const r = cborDecode(buf, pos); arr.push(r.value); pos = r.next; }
        return { value: arr, next: pos + 1 };
      }
      for (let i = 0; i < arg; i++) { const r = cborDecode(buf, pos); arr.push(r.value); pos = r.next; }
      return { value: arr, next: pos };
    }
    case 5: {
      const map = new Map();
      if (arg === -1) {
        while (buf[pos] !== 0xff) {
          const k = cborDecode(buf, pos); const v = cborDecode(buf, k.next);
          map.set(k.value, v.value); pos = v.next;
        }
        return { value: map, next: pos + 1 };
      }
      for (let i = 0; i < arg; i++) {
        const k = cborDecode(buf, pos); const v = cborDecode(buf, k.next);
        map.set(k.value, v.value); pos = v.next;
      }
      return { value: map, next: pos };
    }
    case 7: {
      if (ai === 20) return { value: false, next: pos };
      if (ai === 21) return { value: true, next: pos };
      if (ai === 22) return { value: null, next: pos };
      if (ai === 25) { // float16 (上で読み済みの値)
        const u = arg; const sign = (u & 0x8000) ? -1 : 1; const exp = (u >> 10) & 0x1f; const frac = u & 0x3ff;
        const val = exp === 0 ? sign * (frac / 1024) * Math.pow(2, -14)
          : exp === 31 ? (frac ? NaN : sign * Infinity)
          : sign * (1 + frac / 1024) * Math.pow(2, exp - 15);
        return { value: val, next: pos };
      }
      if (ai === 26) return { value: buf.readFloatBE(offset + 1), next: pos };
      if (ai === 27) return { value: buf.readDoubleBE(offset + 1), next: pos };
      return { value: arg, next: pos }; // simple value
    }
    default: throw new Error('cbor: unsupported major type');
  }
}

// ---------- password (scrypt, PHC 文字列形式) ----------
// 形式: $scrypt$ln=14,r=8,p=1$<salt base64>$<hash base64>
function scryptAsync(password, salt, keylen, params) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, params, (err, key) => err ? reject(err) : resolve(key));
  });
}
async function verifyPassword(phc, password) {
  try {
    const m = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/.exec(phc || '');
    if (!m) return false;
    const params = { N: 2 ** Number(m[1]), r: Number(m[2]), p: Number(m[3]), maxmem: 128 * 1024 * 1024 };
    const salt = Buffer.from(m[4], 'base64');
    const expected = Buffer.from(m[5], 'base64');
    const derived = await scryptAsync(password, salt, expected.length, params);
    return crypto.timingSafeEqual(derived, expected);
  } catch { return false; }
}
export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scryptAsync(password, salt, 64, { N: 2 ** 14, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return `$scrypt$ln=14,r=8,p=1$${salt.toString('base64')}$${key.toString('base64')}`;
}

// ---------- state store ----------
let state = { passkeys: [], sessions: {} };
function loadState() {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.passkeys) && parsed.sessions) state = parsed;
  } catch { /* 初回は空で開始 */ }
}
function saveState() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
}
loadState();

// ---------- sessions (MyBoard 方式: トークンのハッシュだけを保存) ----------
function createSession(authMethod, req) {
  const token = randomToken();
  const hash = tokenHash(token);
  const expires = new Date(Date.now() + SESSION_TTL_MS);
  state.sessions[hash] = {
    created_at: nowIso(),
    expires_at: expires.toISOString(),
    last_seen_at: nowIso(),
    step_up_at: null,
    auth_method: authMethod,
    ip: req.socket.remoteAddress || '',
    user_agent: req.headers['user-agent'] || '',
  };
  saveState();
  return { token, hash, expires };
}
function findSession(token) {
  if (!token) return null;
  const hash = tokenHash(token);
  const s = state.sessions[hash];
  if (!s) return null;
  const now = Date.now();
  if (now > Date.parse(s.expires_at) || now - Date.parse(s.last_seen_at) > SESSION_IDLE_MS) {
    delete state.sessions[hash];
    saveState();
    return null;
  }
  if (now - Date.parse(s.last_seen_at) >= 60000) {
    s.last_seen_at = nowIso();
    saveState();
  }
  return { hash, ...s };
}
function deleteSession(token) {
  if (!token) return;
  const hash = tokenHash(token);
  if (state.sessions[hash]) { delete state.sessions[hash]; saveState(); }
}
function setSessionCookie(res, token, expires) {
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expires.toUTCString()}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${new Date(0).toUTCString()}`);
}
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function requireSession(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  const session = findSession(token);
  return session ? { token, hash: session.hash, session } : null;
}
function assertStepUp(session) {
  const at = session.step_up_at ? Date.parse(session.step_up_at) : 0;
  return at && Date.now() - at <= STEP_UP_WINDOW_MS;
}
function markStepUp(sessionHash) {
  const s = state.sessions[sessionHash];
  if (s) { s.step_up_at = nowIso(); saveState(); }
}

// ---------- WebAuthn ----------
const RP_HASH = sha256(Buffer.from(RP_ID, 'utf8'));
// challenges: key = challenge文字列, value = { kind, sessionHash, expires }
const challenges = new Map();
function saveChallenge(challenge, kind, sessionHash = null) {
  challenges.set(challenge, { kind, sessionHash, expires: Date.now() + CHALLENGE_TTL_MS });
}
function takeChallenge(challenge, kind, sessionHash) {
  const c = challenges.get(challenge);
  if (!c) return false;
  challenges.delete(challenge);
  if (c.expires < Date.now() || c.kind !== kind) return false;
  if (sessionHash !== undefined && c.sessionHash !== sessionHash) return false;
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k);
}, 60000).unref();

function parseClientData(response) {
  const json = JSON.parse(b64urlDecode(response.clientDataJSON).toString('utf8'));
  if (json.crossOrigin === true) throw new Error('cross_origin');
  return json;
}
function checkClientData(json, expectedType, expectedChallenge) {
  if (json.type !== expectedType) throw new Error('bad_type');
  if (json.challenge !== expectedChallenge) throw new Error('bad_challenge');
  if (!ALLOWED_ORIGINS.includes(json.origin)) throw new Error('bad_origin');
}
function parseAuthData(buf) {
  if (buf.length < 37) throw new Error('authdata_short');
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);
  if (!rpIdHash.equals(RP_HASH)) throw new Error('bad_rpid');
  if (!(flags & 0x01)) throw new Error('up_missing');
  const out = { flags, signCount, backedUp: !!(flags & 0x10), deviceType: (flags & 0x08) ? 'multiDevice' : 'singleDevice' };
  if (flags & 0x40) { // AT: attested credential data
    let pos = 37 + 16; // aaguid
    const credIdLen = buf.readUInt16BE(pos); pos += 2;
    out.credentialId = buf.subarray(pos, pos + credIdLen); pos += credIdLen;
    if (out.credentialId.length > 1023) throw new Error('credid_too_long');
    const cose = cborDecode(buf, pos);
    out.coseKey = cose.value;
    out.coseBytes = buf.subarray(pos, cose.next);
  }
  return out;
}
function coseToJwk(coseKey) {
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);
  if (kty === 1) { // OKP (Ed25519)
    return { jwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(coseKey.get(-2)) }, alg };
  }
  if (kty === 2) { // EC2 (P-256)
    const crv = coseKey.get(-1);
    if (crv !== 1) throw new Error('unsupported_curve');
    return { jwk: { kty: 'EC', crv: 'P-256', x: b64url(coseKey.get(-2)), y: b64url(coseKey.get(-3)) }, alg };
  }
  if (kty === 3) { // RSA
    return { jwk: { kty: 'RSA', n: b64url(coseKey.get(-1)), e: b64url(coseKey.get(-2)) }, alg };
  }
  throw new Error('unsupported_kty');
}
function verifySignature(coseKey, data, signature) {
  const { jwk, alg } = coseToJwk(coseKey);
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  if (alg === -8) return crypto.verify(null, data, key, signature);
  if (alg === -7) return crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
  if (alg === -37) return crypto.verify('sha256', data, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  if (alg === -257) return crypto.verify('sha256', data, { key, padding: crypto.constants.RSA_PKCS1_V1_5_PADDING }, signature);
  throw new Error('unsupported_alg');
}
// 登録レスポンスの検証。成功したら保存用クレデンシャル情報を返す。
function verifyRegistration(response, expectedChallenge) {
  const clientData = parseClientData(response);
  checkClientData(clientData, 'webauthn.create', expectedChallenge);
  const attObj = cborDecode(b64urlDecode(response.attestationObject)).value;
  const authData = parseAuthData(attObj.get('authData'));
  if (!authData.coseKey) throw new Error('no_attested_credential');
  coseToJwk(authData.coseKey); // 対応形式か事前確認
  return {
    credential_id: b64url(authData.credentialId),
    public_key_cose: b64url(authData.coseBytes),
    sign_count: authData.signCount,
    credential_device_type: authData.deviceType,
    backed_up: authData.backedUp,
  };
}
// 認証レスポンスの検証。passkey は保存済みレコード。
function verifyAssertion(response, expectedChallenge, passkey) {
  const clientData = parseClientData(response);
  checkClientData(clientData, 'webauthn.get', expectedChallenge);
  const authDataRaw = b64urlDecode(response.authenticatorData);
  const authData = parseAuthData(authDataRaw);
  const clientDataHash = sha256(b64urlDecode(response.clientDataJSON));
  const signed = Buffer.concat([authDataRaw, clientDataHash]);
  const coseKey = cborDecode(b64urlDecode(passkey.public_key_cose)).value;
  const ok = verifySignature(coseKey, signed, b64urlDecode(response.signature));
  if (!ok) throw new Error('bad_signature');
  return { newCounter: authData.signCount };
}
function registrationOptions(sessionHash) {
  const challenge = randomToken();
  saveChallenge(challenge, 'register', sessionHash);
  return {
    challenge,
    rp: { name: RP_NAME, id: RP_ID },
    user: { id: b64url(ADMIN_USER_ID), name: ADMIN_USER_NAME, displayName: RP_NAME },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -37 }, { type: 'public-key', alg: -8 }],
    timeout: 60000,
    attestation: 'none',
    excludeCredentials: state.passkeys.map(p => ({ id: p.credential_id, type: 'public-key' })),
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
  };
}
function authenticationOptions(kind, sessionHash, allowCredentials) {
  const challenge = randomToken();
  saveChallenge(challenge, kind, sessionHash);
  return {
    challenge,
    rpId: RP_ID,
    timeout: 60000,
    userVerification: 'preferred',
    allowCredentials: allowCredentials || [],
  };
}

// ---------- HTTP ----------
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > 128 * 1024) { reject(new Error('too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new Error('bad_json')); }
    });
    req.on('error', reject);
  });
}
// MyBoard と同じ: ログイン試行は IP あたり 30回/10分
const loginHits = new Map();
function hitLoginRateLimit(ip) {
  const now = Date.now();
  const arr = (loginHits.get(ip) || []).filter(t => now - t < 600000);
  arr.push(now);
  loginHits.set(ip, arr);
  return arr.length <= 30;
}
function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xff || req.socket.remoteAddress || '';
}
function checkOriginHeader(req) {
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.includes(origin)) return false;
  return true;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  try {
    // nginx auth_request 用: セッションが有効なら 200、無効なら 401
    if (req.method === 'GET' && p === '/check') {
      const auth = requireSession(req);
      if (!auth) return sendJson(res, 401, { ok: false });
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/healthz') return sendJson(res, 200, { ok: true });
    if (req.method === 'GET' && p === '/config') {
      // ログイン画面が「パスワード未設定」を判定するための公開情報
      return sendJson(res, 200, { password_set: !!PASSWORD_HASH, passkeys_registered: state.passkeys.length });
    }

    if (req.method === 'POST') {
      if (!checkOriginHeader(req)) return sendJson(res, 403, { error: 'forbidden_origin' });
      const body = await readBody(req).catch(() => null);
      if (body === null) return sendJson(res, 400, { error: 'bad_json' });

      if (p === '/login') {
        if (!PASSWORD_HASH) return sendJson(res, 503, { error: 'password_not_set', message: 'パスワードが未設定です。管理者に設定を依頼してください。' });
        if (!hitLoginRateLimit(clientIp(req))) return sendJson(res, 429, { error: 'too_many_requests' });
        if (typeof body.password !== 'string' || !(await verifyPassword(PASSWORD_HASH, body.password))) {
          return sendJson(res, 401, { error: 'invalid_credentials', message: 'パスワードが正しくありません' });
        }
        const s = createSession('password', req);
        setSessionCookie(res, s.token, s.expires);
        return sendJson(res, 200, { ok: true });
      }

      if (p === '/logout') {
        const token = parseCookies(req)[COOKIE_NAME];
        deleteSession(token);
        clearSessionCookie(res);
        return sendJson(res, 200, { ok: true });
      }

      // パスキーログイン（ユーザーネームレス）
      if (p === '/passkeys/login/options') {
        return sendJson(res, 200, authenticationOptions('auth', null, []));
      }
      if (p === '/passkeys/login/verify') {
        const response = body.response;
        if (!response || !response.id) return sendJson(res, 400, { error: 'bad_request' });
        const passkey = state.passkeys.find(pk => pk.credential_id === response.id);
        if (!passkey) return sendJson(res, 400, { error: 'no_passkeys', message: 'パスキーが登録されていません' });
        let presentedChallenge = null;
        try { presentedChallenge = parseClientData(response).challenge; } catch { /* 下で失敗扱い */ }
        if (!presentedChallenge || !takeChallenge(presentedChallenge, 'auth', null)) {
          return sendJson(res, 400, { error: 'challenge_expired', message: 'チャレンジの有効期限が切れました。もう一度お試しください' });
        }
        const userHandle = response.userHandle;
        if (userHandle) {
          const handleStr = b64urlDecode(userHandle).toString('utf8');
          if (handleStr !== ADMIN_USER_ID.toString('utf8')) return sendJson(res, 400, { error: 'no_passkeys' });
        }
        try {
          const info = verifyAssertion(response, presentedChallenge, passkey);
          passkey.sign_count = info.newCounter;
          passkey.last_used_at = nowIso();
          saveState();
        } catch {
          return sendJson(res, 400, { error: 'verification_failed', message: 'パスキーの検証に失敗しました' });
        }
        const s = createSession('passkey', req);
        setSessionCookie(res, s.token, s.expires);
        return sendJson(res, 200, { ok: true });
      }

      // ここから先はセッション必須
      const auth = requireSession(req);
      if (!auth) return sendJson(res, 401, { error: 'unauthorized' });

      if (p === '/me') {
        return sendJson(res, 200, {
          ok: true,
          auth_method: auth.session.auth_method,
          step_up_fresh: !!assertStepUp(auth.session),
          password_set: !!PASSWORD_HASH,
        });
      }

      // 再認証 (step-up): パスワード再入力
      if (p === '/stepup/password') {
        if (!PASSWORD_HASH) return sendJson(res, 503, { error: 'password_not_set' });
        if (typeof body.password !== 'string' || !(await verifyPassword(PASSWORD_HASH, body.password))) {
          return sendJson(res, 401, { error: 'invalid_current_password', message: 'パスワードが正しくありません' });
        }
        markStepUp(auth.hash);
        return sendJson(res, 200, { ok: true });
      }
      // 再認証 (step-up): 既存パスキー
      if (p === '/stepup/passkey/options') {
        if (!state.passkeys.length) return sendJson(res, 400, { error: 'no_passkeys' });
        const allow = state.passkeys.map(pk => ({ id: pk.credential_id, type: 'public-key' }));
        return sendJson(res, 200, authenticationOptions('stepup', auth.hash, allow));
      }
      if (p === '/stepup/passkey/verify') {
        const response = body.response;
        const passkey = response && state.passkeys.find(pk => pk.credential_id === response.id);
        if (!passkey) return sendJson(res, 400, { error: 'no_passkeys' });
        let presentedChallenge = null;
        try { presentedChallenge = parseClientData(response).challenge; } catch { /* 下で失敗扱い */ }
        if (!presentedChallenge || !takeChallenge(presentedChallenge, 'stepup', auth.hash)) {
          return sendJson(res, 400, { error: 'challenge_expired' });
        }
        try {
          const info = verifyAssertion(response, presentedChallenge, passkey);
          passkey.sign_count = info.newCounter;
          passkey.last_used_at = nowIso();
          saveState();
        } catch {
          return sendJson(res, 400, { error: 'verification_failed', message: 'パスキーの検証に失敗しました' });
        }
        markStepUp(auth.hash);
        return sendJson(res, 200, { ok: true });
      }

      // パスキー登録（step-up 必須）
      if (p === '/passkeys/register/options') {
        if (!assertStepUp(auth.session)) return sendJson(res, 403, { error: 'step_up_required', message: 'この操作には再認証が必要です' });
        return sendJson(res, 200, registrationOptions(auth.hash));
      }
      if (p === '/passkeys/register/verify') {
        if (!assertStepUp(auth.session)) return sendJson(res, 403, { error: 'step_up_required', message: 'この操作には再認証が必要です' });
        const response = body.response;
        if (!response || !response.id) return sendJson(res, 400, { error: 'bad_request' });
        if (b64urlDecode(response.id).length > 1023) return sendJson(res, 400, { error: 'verification_failed' });
        let presentedChallenge = null;
        try { presentedChallenge = parseClientData(response).challenge; } catch { /* 下で失敗扱い */ }
        if (!presentedChallenge || !takeChallenge(presentedChallenge, 'register', auth.hash)) {
          return sendJson(res, 400, { error: 'challenge_expired', message: 'チャレンジの有効期限が切れました。もう一度お試しください' });
        }
        let cred;
        try {
          cred = verifyRegistration(response, presentedChallenge);
        } catch (e) {
          console.log('passkey register verify failed:', e && e.message);
          return sendJson(res, 400, { error: 'verification_failed', message: 'パスキーの検証に失敗しました' });
        }
        if (state.passkeys.some(pk => pk.credential_id === cred.credential_id)) {
          return sendJson(res, 400, { error: 'already_registered', message: 'このパスキーは登録済みです' });
        }
        const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 50) : 'パスキー';
        state.passkeys.push({ ...cred, name, created_at: nowIso(), last_used_at: null });
        saveState();
        console.log('passkey registered:', cred.credential_id.slice(0, 8), 'total', state.passkeys.length);
        return sendJson(res, 200, { ok: true });
      }

      return sendJson(res, 404, { error: 'not_found' });
    }

    if (req.method === 'GET' && p === '/passkeys') {
      const auth = requireSession(req);
      if (!auth) return sendJson(res, 401, { error: 'unauthorized' });
      return sendJson(res, 200, state.passkeys.map(pk => ({
        credential_id: pk.credential_id, name: pk.name,
        created_at: pk.created_at, last_used_at: pk.last_used_at,
      })));
    }
    if (req.method === 'DELETE' && p.startsWith('/passkeys/')) {
      const auth = requireSession(req);
      if (!auth) return sendJson(res, 401, { error: 'unauthorized' });
      if (!assertStepUp(auth.session)) return sendJson(res, 403, { error: 'step_up_required', message: 'この操作には再認証が必要です' });
      const id = decodeURIComponent(p.slice('/passkeys/'.length));
      const idx = state.passkeys.findIndex(pk => pk.credential_id === id);
      if (idx < 0) return sendJson(res, 404, { error: 'not_found' });
      state.passkeys.splice(idx, 1);
      saveState();
      return sendJson(res, 200, { ok: true });
    }

    return sendJson(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error('request error', e);
    return sendJson(res, 500, { error: 'internal_error' });
  }
});

import { pathToFileURL } from 'node:url';
// git-sync の symlink 経由で起動されると argv[1] と import.meta.url (実パス解決済み) が
// 一致しないため、realpath で揃えてから比較する
let isMainModule = false;
try {
  isMainModule = !!process.argv[1] &&
    import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href;
} catch { isMainModule = false; }
if (isMainModule) {
  if (!AUTH_SECRET) {
    console.error('AUTH_SECRET が未設定です。k8s Secret (nemu-link-auth-secret) を設定してください。起動を中止します。');
    process.exit(1);
  }
  server.listen(PORT, () => {
    console.log(`link-auth listening on :${PORT} rpId=${RP_ID} passwordSet=${!!PASSWORD_HASH} passkeys=${state.passkeys.length}`);
  });
}
export { server };
