// 管理ページ用 WebAuthn クライアント補助
// サーバ (link-auth) と base64url JSON でやり取りするための最小実装。
function b64urlToBuffer(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function prepareCreationOptions(json) {
  const opts = { ...json };
  opts.challenge = b64urlToBuffer(json.challenge);
  opts.user = { ...json.user, id: b64urlToBuffer(json.user.id) };
  if (json.excludeCredentials) {
    opts.excludeCredentials = json.excludeCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
  }
  return opts;
}
function prepareRequestOptions(json) {
  const opts = { ...json };
  opts.challenge = b64urlToBuffer(json.challenge);
  if (json.allowCredentials) {
    opts.allowCredentials = json.allowCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
  }
  return opts;
}
function serializeCredential(cred) {
  const r = cred.response;
  const out = { id: cred.id, type: cred.type, clientDataJSON: bufferToB64url(r.clientDataJSON) };
  if (r.attestationObject) out.attestationObject = bufferToB64url(r.attestationObject);
  if (r.authenticatorData) out.authenticatorData = bufferToB64url(r.authenticatorData);
  if (r.signature) out.signature = bufferToB64url(r.signature);
  out.userHandle = r.userHandle ? bufferToB64url(r.userHandle) : null;
  return out;
}
async function apiJson(path, method = 'GET', body) {
  const res = await fetch('/kokonyasu/auth-api' + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* empty */ }
  return { status: res.status, json };
}
