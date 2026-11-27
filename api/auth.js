const crypto = require('node:crypto');

const COOKIE = '__Host-rastreios_session';
const DURATION = 8 * 60 * 60;

function equal(a, b) {
  const hash = v =>
    crypto.createHash('sha256').update(v).digest();
  return crypto.timingSafeEqual(hash(a), hash(b));
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret)
    .update('rastreios-session:' + value)
    .digest('hex');
}

function authenticated(req, secret) {
  const cookies = req.headers.cookie || '';
  const token = cookies.split(';')
    .map(c => c.trim())
    .find(c => c.startsWith(COOKIE + '='))
    ?.slice(COOKIE.length + 1);

  if (!token) return false;

  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const [expires, nonce, signature] = parts;

  if (!/^\d+$/.test(expires)) return false;
  if (Number(expires) <= Date.now()) return false;

  return equal(
    signature,
    sign(expires + '.' + nonce, secret)
  );
}

module.exports = function (req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const secret = process.env.ADMIN_PASSWORD;

  if (!secret) {
    return res.status(503).json({ ok: false });
  }

  if (req.method === 'GET') {
    return res.status(200).json({
      ok: authenticated(req, secret)
    });
  }

  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie',
      COOKIE + '=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
    );
    return res.status(200).json({ ok: true });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false });
  }

  const password = req.body?.password;

  if (typeof password !== 'string' ||
      !equal(password, secret)) {
    return res.status(401).json({ ok: false });
  }

  const expires = Date.now() + DURATION * 1000;
  const nonce = crypto.randomBytes(32).toString('hex');
  const value = expires + '.' + nonce;
  const token = value + '.' + sign(value, secret);

  res.setHeader('Set-Cookie',
    COOKIE + '=' + token +
    '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' +
    DURATION
  );

  return res.status(200).json({ ok: true });
};
