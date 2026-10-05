import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createBashGrantVerifier } from './bash-grant.ts';
import type { ConfidentialBashResult } from './confidential-bash.ts';
import { SandboxBusyError } from './sandbox-errors.ts';
import { AgentCapacityError } from './agent-capacity.ts';

/** Place behind the enclave's EHBP terminator; never expose this plaintext port. */
export function createConfidentialBashServer(options: {
  publicKey: string;
  execute: (tenant: string, command: string, timeout: number, signal: AbortSignal, beforeDispatch: () => void) => Promise<ConfidentialBashResult>;
}) {
  const boot = randomBytes(32).toString('hex');
  let validatedAt = NaN;
  const authorize = createBashGrantVerifier(options.publicKey, boot, () => {
    const time = Date.now(); validatedAt = time; return time;
  });
  const active = new Map<AbortController, Promise<void>>();
  let closing = false;
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json'); response.setHeader('Cache-Control', 'no-store');
    if (request.method === 'GET' && request.url === '/healthz') { response.end('{"version":1}'); return; }
    if (request.method !== 'POST' || request.url !== '/private') { response.writeHead(404).end('{}'); return; }
    // This authenticated encrypted body proves that no command was dispatched.
    // An outer HTTP error alone cannot safely release an uncertainty journal.
    if (closing || active.size >= 100) { response.end('{"version":1,"busy":true}'); return; }
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
        const monotonicStart = performance.now();
        validatedAt = NaN;
        const grant = authorize(body.token, body.command, body.timeout);
        // Verification and this copy are synchronous. Each request captures
        // the exact sample that passed the verifier's rollback/expiry checks.
        const verifiedWall = validatedAt; accepted = true;
        // Queue admission and guest setup can consume most of a grant's life.
        // A monotonic deadline also prevents a backward wall-clock adjustment
        // from extending authority while this request waits.
        const deadline = monotonicStart + Math.max(0, grant.expires - verifiedWall);
        const result = await options.execute(grant.tenant, body.command, body.timeout, controller.signal, () => {
          controller.signal.throwIfAborted();
          if (Date.now() >= grant.expires || performance.now() >= deadline) throw new SandboxBusyError();
        });
        response.end(JSON.stringify(result));
      } catch (error) {
        // Commands, identities, tokens and child diagnostics never appear here.
        if (!response.destroyed) {
          if (accepted && (error instanceof SandboxBusyError || error instanceof AgentCapacityError))
            response.end('{"version":1,"busy":true}');
          else response.writeHead(accepted ? 503 : 403).end('{}');
        }
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
