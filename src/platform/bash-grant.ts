import { createHash, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';

export interface BashGrant { version: 1; audience: 'sure-confidential-bash'; boot: string; id: string; tenant: string; command: string; timeout: number; expires: number }
const denied = () => new Error('Bash grant rejected');
export function commandDigest(command: string) { return createHash('sha256').update(command).digest('hex'); }
function valid(grant: BashGrant) {
  if (!grant || Object.keys(grant).sort().join(',') !== 'audience,boot,command,expires,id,tenant,timeout,version'
    || grant.version !== 1 || grant.audience !== 'sure-confidential-bash' || !/^[a-f0-9]{64}$/.test(grant.boot)
    || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(grant.id) || !/^[a-z0-9][a-z0-9-]{0,79}$/.test(grant.tenant)
    || !/^[a-f0-9]{64}$/.test(grant.command) || !Number.isInteger(grant.timeout) || grant.timeout < 1 || grant.timeout > 60
    || !Number.isSafeInteger(grant.expires)) throw denied();
}
export function signBashGrant(grant: BashGrant, key: KeyObject) {
  valid(grant);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw denied();
  const payload = Buffer.from(JSON.stringify(grant)).toString('base64url');
  return `${payload}.${sign(null, Buffer.from(payload), key).toString('base64url')}`;
}
export function createBashGrantVerifier(publicKey: string, boot: string, now = Date.now) {
  const key = createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519' || !/^[a-f0-9]{64}$/.test(boot)) throw denied();
  const used = new Map<string, number>();
  let latestTime = now();
  return (token: unknown, command: unknown, timeout: unknown) => {
    if (typeof token !== 'string' || token.length > 2048 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)
      || typeof command !== 'string' || !command.trim() || Buffer.byteLength(command) > 16_000 || command.includes('\0')) throw denied();
    const [payload, signature] = token.split('.');
    if (!verify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64url'))) throw denied();
    let grant: BashGrant;
    try { grant = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); valid(grant); } catch { throw denied(); }
    const time = now();
    // Once an expired replay record is discarded, a backward clock adjustment
    // must not make that grant valid again during the same enclave boot.
    if (!Number.isSafeInteger(time) || time < latestTime) throw denied();
    latestTime = time;
    if (grant.boot !== boot || grant.command !== commandDigest(command) || grant.timeout !== timeout
      || grant.expires <= time || grant.expires > time + 90_000) throw denied();
    for (const [id, expiry] of used) if (expiry <= time) used.delete(id);
    if (used.has(grant.id) || used.size >= 10_000) throw denied();
    // Consume before dispatch, including failed/uncertain executions. A caller
    // must never turn a lost reply into a second execution of the same grant.
    used.set(grant.id, grant.expires);
    return grant;
  };
}
