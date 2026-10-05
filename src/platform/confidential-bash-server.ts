import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { createBashGrantVerifier } from './bash-grant.ts';
import type { ConfidentialBashResult } from './confidential-bash.ts';

/** Place behind the enclave's EHBP terminator; never expose this plaintext port. */
export function createConfidentialBashServer(options: {
  publicKey: string;
  execute: (tenant: string, command: string, timeout: number, signal: AbortSignal) => Promise<ConfidentialBashResult>;
}) {
  const boot = randomBytes(32).toString('hex');
  const authorize = createBashGrantVerifier(options.publicKey, boot);
  const active = new Map<AbortController, Promise<void>>();
  let closing = false;
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json'); response.setHeader('Cache-Control', 'no-store');
    if (request.method === 'GET' && request.url === '/healthz') { response.end('{"version":1}'); return; }
    if (request.method !== 'POST' || request.url !== '/private') { response.writeHead(404).end('{}'); return; }
    if (closing || active.size >= 100) { response.writeHead(503).end('{}'); return; }
    const controller = new AbortController();
    response.once('close', () => { if (!response.writableFinished) controller.abort(); });
    const work = (async () => {
      let accepted = false;
      try {
        let size = 0; const chunks: Buffer[] = [];
        for await (const chunk of request) { size += chunk.length; if (size > 100_000) throw new Error(); chunks.push(chunk); }
        controller.signal.throwIfAborted();
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || Array.isArray(body)) throw new Error();
        const keys = Object.keys(body).sort().join(',');
        // The boot nonce must itself travel in an authenticated encrypted reply.
        if (keys === 'operation' && body.operation === 'status') {
          response.end(JSON.stringify({ version: 1, boot })); return;
        }
        if (keys !== 'command,operation,timeout,token' || body.operation !== 'execute') throw new Error();
        const grant = authorize(body.token, body.command, body.timeout); accepted = true;
        const result = await options.execute(grant.tenant, body.command, body.timeout, controller.signal);
        response.end(JSON.stringify(result));
      } catch {
        // Commands, identities, tokens and child diagnostics never appear here.
        if (!response.destroyed) response.writeHead(accepted ? 503 : 403).end('{}');
      } finally { active.delete(controller); }
    })();
    active.set(controller, work);
  });
  server.requestTimeout = 10_000; server.headersTimeout = 5_000; server.maxHeadersCount = 20;
  return { server, async close() {
    closing = true;
    const stopped = new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    for (const controller of active.keys()) controller.abort();
    // HTTP disconnection does not imply that a sandbox has finished cleanup.
    server.closeAllConnections();
    await Promise.allSettled([...active.values()]);
    await stopped;
  } };
}
