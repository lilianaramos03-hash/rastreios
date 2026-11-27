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

  const estados = [
    'Por rever',
    'Em análise',
    'Concluído'
  ];

  const uuidValido = id =>
    typeof id === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);

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

            if (b.tipo_formulario === 'educadora') {
        const ics = b.respostas_ics;

        if (
          !nomeValido(b.primeiro_nome) ||
          !nomeValido(b.ultimo_nome) ||
          !objetoValido(ics) ||
          Object.keys(ics).length !== 7 ||
          !Array.from({ length: 7 }, (_, i) =>
            Number.isInteger(ics[String(i + 1)]) &&
            ics[String(i + 1)] >= 1 &&
            ics[String(i + 1)] <= 5
          ).every(Boolean) ||
          JSON.stringify(b).length > 50000
        ) {
          return res.status(400).json({
            ok: false,
            error: 'Dados incompletos ou respostas inválidas.'
          });
        }

        const registoEducadora = {
          primeiro_nome: b.primeiro_nome.trim(),
          ultimo_nome: b.ultimo_nome.trim(),
          data_nascimento: null,
          tipo_formulario: 'educadora',
          respostas_edl: {},
          respostas_abertas: {},
          respostas_ics: ics,
          observacoes: String(b.observacoes || '').slice(0, 5000),
          confirmacao_revisao: false,
          autorizacao: false,
          versao_formulario: '0.7',
          estado: 'Por rever'
        };

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            ...headers,
            Prefer: 'return=minimal'
          },
          body: JSON.stringify(registoEducadora)
        });

        if (!response.ok) throw new Error();

        return res.status(201).json({ ok: true });
      }

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

    if (req.method === 'PATCH' || req.method === 'DELETE') {
      if (!authenticated(req)) {
        return res.status(401).json({ ok: false });
      }

      if (req.headers.origin !== 'https://rastreios-linguagem.vercel.app') {
        return res.status(403).json({ ok: false });
      }

      const b = req.body || {};
      const id = b.id;

      if (!uuidValido(id)) {
        return res.status(400).json({
          ok: false,
          error: 'Identificador inválido.'
        });
      }

      const destino = endpoint + '?id=eq.' + id;

      if (req.method === 'DELETE') {
        if (b.confirmacao !== true) {
          return res.status(400).json({
            ok: false,
            error: 'Confirmação necessária.'
          });
        }

        const response = await fetch(destino, {
          method: 'DELETE',
          headers: {
            ...headers,
            Prefer: 'return=representation'
          }
        });

        if (!response.ok) throw new Error();

        const eliminados = await response.json();

        if (!eliminados.length) {
          return res.status(404).json({ ok: false });
        }

        return res.status(200).json({ ok: true });
      }

      const alteracoes = {};

      if (b.estado !== undefined) {
        if (!estados.includes(b.estado)) {
          return res.status(400).json({
            ok: false,
            error: 'Estado inválido.'
          });
        }

        alteracoes.estado = b.estado;
      }

      let destinoAtualizacao = destino;

      if (b.nota !== undefined) {
        if (
          typeof b.nota !== 'string' ||
          !b.nota.trim() ||
          b.nota.length > 5000
        ) {
          return res.status(400).json({
            ok: false,
            error: 'Nota inválida.'
          });
        }

        const consulta = await fetch(
          destino + '&select=notas_profissionais,ultima_atualizacao',
          { headers }
        );

        if (!consulta.ok) throw new Error();

        const dados = await consulta.json();

        if (!dados.length) {
          return res.status(404).json({ ok: false });
        }

        const notas = dados[0].notas_profissionais || [];

        if (!Array.isArray(notas)) throw new Error();

        alteracoes.notas_profissionais = [
          ...notas,
          {
            id: crypto.randomUUID(),
            texto: b.nota.trim(),
            data: new Date().toISOString()
          }
        ];

        const anterior = dados[0].ultima_atualizacao;

        destinoAtualizacao += anterior
          ? '&ultima_atualizacao=eq.' + encodeURIComponent(anterior)
          : '&ultima_atualizacao=is.null';
      }

      if (!Object.keys(alteracoes).length) {
        return res.status(400).json({
          ok: false,
          error: 'Nenhuma alteração indicada.'
        });
      }

      alteracoes.ultima_atualizacao =
        new Date().toISOString();

      const response = await fetch(destinoAtualizacao, {
        method: 'PATCH',
        headers: {
          ...headers,
          Prefer: 'return=representation'
        },
        body: JSON.stringify(alteracoes)
      });

      if (!response.ok) throw new Error();

      const atualizados = await response.json();

      if (!atualizados.length) {
        return res.status(409).json({
          ok: false,
          error: 'Registo alterado ou inexistente. Atualize a página.'
        });
      }

      return res.status(200).json({
        ok: true,
        rastreio: atualizados[0]
      });
    }

    return res.status(405).json({ ok: false });

  } catch {
    return res.status(500).json({
      ok: false,
      error: 'Não foi possível concluir a operação.'
    });
  }
};
