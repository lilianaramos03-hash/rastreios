const crypto = require('node:crypto');

function authenticated(req) {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret) return false;

  const token = (req.headers.cookie || '')
    .split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('__Host-rastreios_session='))
    ?.split('=')[1];

  if (!token) return false;

  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const [expires, nonce, signature] = parts;

  if (!/^\d+$/.test(expires)) return false;
  if (Number(expires) <= Date.now()) return false;

  const expected = crypto.createHmac('sha256', secret)
    .update('rastreios-session:' + expires + '.' + nonce)
    .digest('hex');

  if (!/^[a-f0-9]{64}$/.test(signature)) return false;

  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expected, 'hex')
  );
}

module.exports = async function (req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    return res.status(503).json({
      ok: false,
      error: 'Base de dados não configurada.'
    });
  }

  const endpoint = url.replace(/\/$/, '') +
    '/rest/v1/rastreios';

  const headers = {
    apikey: key,
    'Content-Type': 'application/json'
  };

  try {
    if (req.method === 'GET') {
      if (!authenticated(req)) {
        return res.status(401).json({ ok: false });
      }

      const response = await fetch(
        endpoint + '?select=*&order=data_submissao.desc',
        { headers }
      );

      if (!response.ok) throw new Error();

      return res.status(200).json({
        ok: true,
        rastreios: await response.json()
      });
    }

    if (req.method === 'POST') {
      const b = req.body || {};

      const nomeValido = v =>
        typeof v === 'string' &&
        v.trim().length > 0 &&
        v.length <= 100;

      const objetoValido = v =>
        v && typeof v === 'object' &&
        !Array.isArray(v);

      const data = new Date(b.data_nascimento);

      if (
        !nomeValido(b.primeiro_nome) ||
        !nomeValido(b.ultimo_nome) ||
        !/^\d{4}-\d{2}-\d{2}$/.test(b.data_nascimento || '') ||
        !Number.isFinite(data.getTime()) ||
        data.toISOString().slice(0, 10) !== b.data_nascimento ||
        data > new Date() ||
        b.autorizacao !== true ||
        b.confirmacao_revisao !== true ||
        !objetoValido(b.respostas_edl) ||
        !objetoValido(b.respostas_abertas) ||
        JSON.stringify(b).length > 50000
      ) {
        return res.status(400).json({
          ok: false,
          error: 'Dados incompletos ou inválidos.'
        });
      }

      const registo = {
        primeiro_nome: b.primeiro_nome.trim(),
        ultimo_nome: b.ultimo_nome.trim(),
        data_nascimento: b.data_nascimento,
        tipo_formulario: 'familia',
        respostas_edl: b.respostas_edl,
        respostas_abertas: b.respostas_abertas,
        observacoes: String(b.observacoes || '').slice(0, 5000),
        confirmacao_revisao: true,
        autorizacao: true,
        versao_formulario: '0.5',
        estado: 'Por rever'
      };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          ...headers,
          Prefer: 'return=minimal'
        },
        body: JSON.stringify(registo)
      });

      if (!response.ok) throw new Error();

      return res.status(201).json({ ok: true });
    }

    return res.status(405).json({ ok: false });

  } catch {
    return res.status(500).json({
      ok: false,
      error: 'Não foi possível concluir a operação.'
    });
  }
};
