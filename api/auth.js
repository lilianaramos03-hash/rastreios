const crypto = require('node:crypto');

module.exports = function (req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false });
  }

  const secret = process.env.ADMIN_PASSWORD;

  if (!secret) {
    return res.status(503).json({ ok: false });
  }

  const password = req.body?.password;

  if (typeof password !== 'string') {
    return res.status(400).json({ ok: false });
  }

  const hash = value =>
    crypto.createHash('sha256').update(value).digest();

  const valid = crypto.timingSafeEqual(
    hash(password),
    hash(secret)
  );

  if (!valid) {
    return res.status(401).json({ ok: false });
  }

  return res.status(200).json({ ok: true });
};
