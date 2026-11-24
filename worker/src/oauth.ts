import { DurableObject } from 'cloudflare:workers';
import { createHash, randomBytes } from 'node:crypto';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { approvalStore, ownerSessionCookie, passkeyOrigin, type PasskeyEnv } from './passkeys';

export type OAuthEnv = PasskeyEnv & {
  OAUTH_GRANTS: DurableObjectNamespace<OAuthGrant>;
  OAUTH_REDIRECT_URI?: string;
};

const scope = 'pasta:mcp';
const minute = 60_000;
const accessLifetime = 15 * minute;
const grantLifetime = 7 * 24 * 60 * minute;
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const secret = () => randomBytes(32).toString('base64url');
const opaque = /^[A-Za-z0-9_-]{43}$/u;
const noCache = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };
type Authorization = { client: string; redirect: string; resource: string; challenge: string; state: string };
type Grant = Authorization & {
  expires: number; code?: string; access?: string; accessExpires?: number; refresh?: string;
};

export class OAuthGrant extends DurableObject<OAuthEnv> {
  #indexedUntil = 0;

  async #publishConnection(id: string, redirect: string, expires: number) {
    if (this.#indexedUntil === expires) return;
    const callback = new URL(redirect);
    try {
      await approvalStore(this.env).recordMcpConnection({
        id, name: redirect === this.env.OAUTH_REDIRECT_URI ? 'OpenBot' : 'Local MCP client',
        callback: callback.host, connectedAt: expires - grantLifetime, expires,
      });
      this.#indexedUntil = expires;
    } catch {
      console.warn('Could not update the MCP connection inventory.');
    }
  }

  async start(auth: Authorization) {
    await this.ctx.storage.put('grant', { ...auth, expires: Date.now() + 5 * minute });
    await this.ctx.storage.setAlarm(Date.now() + 5 * minute);
  }

  async pending() {
    const grant = await this.ctx.storage.get<Grant>('grant');
    return Boolean(grant && grant.expires > Date.now() && !grant.code && !grant.access);
  }

  async approve() {
    return this.ctx.storage.transaction(async tx => {
      const grant = await tx.get<Grant>('grant');
      if (!grant || grant.expires <= Date.now() || grant.code || grant.access) return null;
      const code = secret();
      await tx.put('grant', { ...grant, code: digest(code), expires: Math.min(grant.expires, Date.now() + minute) });
      return { code, redirect: grant.redirect, state: grant.state };
    });
  }

  async exchange(id: string, client: string, resource: string, proof: string, redirect: string | null, verifier: string | null) {
    const result = await this.ctx.storage.transaction(async tx => {
      const grant = await tx.get<Grant>('grant');
      const now = Date.now();
      if (!grant || grant.expires <= now || grant.client !== client || grant.resource !== resource) return null;
      const codeExchange = verifier !== null;
      if (codeExchange
        ? grant.code !== digest(proof) || redirect !== grant.redirect || digest(verifier) !== grant.challenge
        : grant.refresh !== digest(proof)) return null;

      const access = secret();
      const refresh = secret();
      const expires = codeExchange ? now + grantLifetime : grant.expires;
      const accessExpires = Math.min(expires, now + accessLifetime);
      await tx.put('grant', { ...grant, code: undefined, access: digest(access), refresh: digest(refresh), accessExpires, expires });
      await tx.setAlarm(expires);
      return { access, refresh, expiresIn: Math.floor((accessExpires - now) / 1000), redirect: grant.redirect, expires };
    });
    if (result) await this.#publishConnection(id, result.redirect, result.expires);
    return result;
  }

  async accepts(id: string, resource: string, token: string) {
    const grant = await this.ctx.storage.get<Grant>('grant');
    if (!grant || grant.resource !== resource || (grant.accessExpires ?? 0) <= Date.now() || grant.access !== digest(token)) return false;
    await this.#publishConnection(id, grant.redirect, grant.expires);
    return true;
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
  }
}

function config(env: OAuthEnv) {
  const origin = passkeyOrigin(env)?.origin;
  if (!origin || !env.OAUTH_REDIRECT_URI) return;
  return { origin, resource: origin + '/mcp' };
}

function clientForRedirect(value: unknown, env: OAuthEnv) {
  if (typeof value !== 'string' || value.length > 512) return null;
  try {
    const url = new URL(value);
    if (url.href !== value || url.username || url.password || url.hash || url.search) return null;
    const openBotLoopback = url.protocol === 'http:' && Boolean(url.port) &&
      ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) &&
      ['/mcp-auth', '/callback'].includes(url.pathname);
    if (!openBotLoopback && !(url.protocol === 'https:' && value === env.OAUTH_REDIRECT_URI)) return null;
    return { redirect: value, client: 'pasta-' + digest(value) };
  } catch { return null; }
}

const metadataPath = '/.well-known/oauth-protected-resource/mcp';
const authorizationPath = '/.well-known/oauth-authorization-server';
const response = (body: unknown, status = 200) => Response.json(body, { status, headers: noCache });
const invalid = (error = 'invalid_request', status = 400) => response({ error }, status);
const store = (env: OAuthEnv, id: string) => env.OAUTH_GRANTS.getByName(id);
const parts = (token: string) => {
  const [id, secretPart, extra] = token.split('.');
  return extra === undefined && opaque.test(id) && opaque.test(secretPart) ? { id, secretPart } : null;
};

export function oauthUnauthorized(env: OAuthEnv) {
  const settings = config(env);
  return new Response('Unauthorized', { status: 401, headers: settings
    ? { ...noCache, 'WWW-Authenticate': `Bearer resource_metadata="${settings.origin}${metadataPath}", scope="${scope}"` }
    : noCache });
}

export async function authenticatedOAuthGrant(env: OAuthEnv, token: string) {
  const settings = config(env);
  const parsed = parts(token);
  if (settings && parsed && await store(env, parsed.id).accepts(parsed.id, settings.resource, parsed.secretPart)) return parsed.id;
}

export async function oauthRoute(request: Request, env: OAuthEnv) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/oauth/') && url.pathname !== authorizationPath &&
      url.pathname !== metadataPath && url.pathname !== '/.well-known/oauth-protected-resource') return;
  const settings = config(env);
  if (!settings || url.origin !== settings.origin) return invalid('not_found', 404);
  const { origin, resource } = settings;

  if (request.method === 'GET') {
    if (url.pathname === metadataPath || url.pathname === '/.well-known/oauth-protected-resource') return response({
      resource, authorization_servers: [origin], scopes_supported: [scope], bearer_methods_supported: ['header'],
    });
    if (url.pathname === authorizationPath) return response({
      issuer: origin, authorization_endpoint: origin + '/oauth/authorize', token_endpoint: origin + '/oauth/token',
      registration_endpoint: origin + '/oauth/register', scopes_supported: [scope],
      response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'],
      authorization_response_iss_parameter_supported: true,
    });
    if (url.pathname === '/oauth/authorize') {
      const query = url.searchParams;
      const registration = clientForRedirect(query.get('redirect_uri'), env);
      if (!registration) return invalid();
      const { redirect, client } = registration;
      const challenge = query.get('code_challenge') ?? '';
      const state = query.get('state') ?? '';
      if (new Set(query.keys()).size !== Array.from(query).length || query.get('client_id') !== client ||
          query.get('response_type') !== 'code' ||
          query.get('code_challenge_method') !== 'S256' || !opaque.test(challenge) ||
          (query.get('resource') ?? resource) !== resource || (query.get('scope') ?? scope) !== scope ||
          !state || state.length > 1024) return invalid();
      const id = secret();
      await store(env, id).start({ client, redirect, resource, challenge, state });
      const nonce = secret();
      return new Response(consentPage(nonce, id), { headers: {
        ...noCache, 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; connect-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
      } });
    }
    return invalid('not_found', 404);
  }

  if (request.method !== 'POST') return invalid('invalid_request', 405);
  const length = request.headers.get('Content-Length') ?? '';
  if (!/^\d{1,4}$/u.test(length) || Number(length) > 8192) return invalid('invalid_request', 413);
  const mediaType = request.headers.get('Content-Type')?.split(';')[0].trim();
  if (url.pathname === '/oauth/register') {
    if (mediaType !== 'application/json') return invalid();
    const registration = await request.json().catch(() => null) as Record<string, unknown> | null;
    const redirects = registration?.redirect_uris;
    const registered = Array.isArray(redirects) && redirects.length === 1 ? clientForRedirect(redirects[0], env) : null;
    if (!registered) return invalid('invalid_redirect_uri');
    if ((registration?.token_endpoint_auth_method ?? 'none') !== 'none') return invalid('invalid_client_metadata');
    return response({
      client_id: registered.client, redirect_uris: [registered.redirect], token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scope,
    }, 201);
  }

  if (url.pathname === '/oauth/options' || url.pathname === '/oauth/approve') {
    if (mediaType !== 'application/json' || request.headers.get('Origin') !== origin) return invalid();
    const proof = await request.json().catch(() => null) as Record<string, unknown> | null;
    if (typeof proof?.request !== 'string' || !opaque.test(proof.request)) return invalid();
    const context = ':oauth:' + proof.request;
    if (url.pathname === '/oauth/options') {
      if (!await store(env, proof.request).pending()) return invalid('invalid_grant');
      const options = await approvalStore(env).signInOptions(context);
      return options ? response(options) : invalid('access_denied', 403);
    }
    if (!proof.response) return invalid();
    const ownerSession = await approvalStore(env).signIn(proof.id, proof.response as AuthenticationResponseJSON, context);
    if (!ownerSession) return invalid('access_denied', 403);
    const approved = await store(env, proof.request).approve();
    if (!approved) return invalid('invalid_grant');
    const callback = new URL(approved.redirect);
    callback.searchParams.set('code', proof.request + '.' + approved.code);
    callback.searchParams.set('state', approved.state);
    callback.searchParams.set('iss', origin);
    return Response.json({ redirect: callback.href }, {
      headers: { ...noCache, 'Set-Cookie': ownerSessionCookie(ownerSession) },
    });
  }

  if (url.pathname !== '/oauth/token' || mediaType !== 'application/x-www-form-urlencoded') return invalid();
  const form = new URLSearchParams(await request.text());
  if (new Set(form.keys()).size !== Array.from(form).length || (form.get('resource') ?? resource) !== resource) return invalid();
  const client = form.get('client_id') ?? '';
  if (!/^pasta-[A-Za-z0-9_-]{43}$/u.test(client)) return invalid('invalid_client');
  const grantType = form.get('grant_type');
  if (grantType !== 'authorization_code' && grantType !== 'refresh_token') return invalid('unsupported_grant_type');
  const isCode = grantType === 'authorization_code';
  const verifier = isCode ? form.get('code_verifier') ?? '' : null;
  if ((verifier !== null && !/^[A-Za-z0-9._~-]{43,128}$/u.test(verifier)) || (form.get('scope') ?? scope) !== scope) return invalid();
  const parsed = parts(form.get(isCode ? 'code' : 'refresh_token') ?? '');
  if (!parsed) return invalid('invalid_grant');
  const tokens = await store(env, parsed.id).exchange(parsed.id, client, resource, parsed.secretPart, form.get('redirect_uri'), verifier);
  return tokens ? response({
    access_token: parsed.id + '.' + tokens.access, refresh_token: parsed.id + '.' + tokens.refresh,
    token_type: 'Bearer', expires_in: tokens.expiresIn, scope,
  }) : invalid('invalid_grant');
}

function consentPage(nonce: string, id: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect OpenBot to PaSTA</title>
<link rel="stylesheet" href="/passkeys/style.css">
</head>
<body>
<div class="shell">
<header class="brand">
  <span class="brand-mark" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
      <path d="m12 3 7 3v5c0 4-2.5 7.5-7 10-4.5-2.5-7-6-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/>
    </svg>
  </span>
  <span>PaSTA</span>
</header>
<main class="card">
  <h1>Connect OpenBot to PaSTA</h1>
  <p class="lead">OpenBot can view enrolled hosts and request maintenance. Each command still requires your passkey approval.</p>
  <div class="actions"><button type="button">Connect with passkey</button></div>
  <p class="status" data-tone="error" role="status"></p>
</main>
</div>
<script nonce="${nonce}" src="/passkeys/webauthn.js"></script><script nonce="${nonce}">
const button = document.querySelector('button');
const status = document.querySelector('[role=status]');
async function post(path, body) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error();
  return response.json();
}
button.onclick = async () => {
  button.disabled = true;
  try {
    const { id, options } = await post('/oauth/options', { request: '${id}' });
    const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
    const { redirect } = await post('/oauth/approve', { request: '${id}', id, response });
    location.replace(redirect);
  } catch {
    status.textContent = 'Could not connect. Try again or restart sign-in from OpenBot.';
    button.disabled = false;
  }
};
</script>
</body>
</html>`;
}
