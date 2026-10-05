import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** OCI createRuntime hook: verify effective kernel limits before user code starts. */
export async function verifyBashCgroup(state: unknown, read = (path: string) => readFile(path, 'utf8')) {
  if (!state || typeof state !== 'object' || !('id' in state) || typeof state.id !== 'string'
    || !/^sure-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(state.id)
    || !('pid' in state) || !Number.isSafeInteger(state.pid) || (state.pid as number) < 2) throw new Error('Invalid runtime state');
  const membership = (await read(`/proc/${state.pid}/cgroup`)).trim().split('\n');
  // Support only unified cgroup v2 with a dedicated sandbox leaf. Missing
  // controllers or silently skipped limits must fail before Bash is released.
  if (membership.length !== 1 || !membership[0].startsWith('0::/')) throw new Error('Unsupported resource isolation');
  const path = membership[0].slice(3);
  if (path !== '/' + state.id) throw new Error('Unexpected resource scope');
  const expected = { 'memory.max': '536870912', 'memory.swap.max': '0', 'pids.max': '64', 'cpu.max': '100000 100000' };
  await Promise.all(Object.entries(expected).map(async ([name, value]) => {
    if ((await read('/sys/fs/cgroup' + path + '/' + name)).trim() !== value) throw new Error('Resource limit missing');
  }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const deadline = setTimeout(() => process.exit(1), 5000);
  try {
    const chunks: Buffer[] = []; let size = 0;
    for await (const chunk of process.stdin) { size += chunk.length; if (size > 8192) throw new Error(); chunks.push(chunk); }
    await verifyBashCgroup(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  } catch { process.exitCode = 1; }
  finally { clearTimeout(deadline); }
}
