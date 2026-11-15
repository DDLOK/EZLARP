export async function onRequestPost(context) {
  const { request, env } = context;
  const backend = env.BACKEND_URL;
  if (!backend) {
    return new Response('BACKEND_URL not set on Cloudflare Pages', { status: 500 });
  }

  const upstream = await fetch(backend.replace(/\/$/, '') + '/decompile', {
    method: 'POST',
    headers: {
      'x-ezlarp-key': env.BACKEND_KEY || '',
      'content-type': request.headers.get('content-type') || 'application/octet-stream',
    },
    body: request.body,
    duplex: 'half',
  });

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'content-type': upstream.headers.get('content-type') || 'application/json' },
  });
}

export async function onRequestGet(context) {
  const backend = context.env.BACKEND_URL;
  if (!backend) return new Response(JSON.stringify({ ok: false, err: 'no BACKEND_URL' }), { status: 500 });
  const upstream = await fetch(backend.replace(/\/$/, '') + '/health');
  return new Response(await upstream.text(), { status: upstream.status, headers: { 'content-type': 'application/json' } });
}
