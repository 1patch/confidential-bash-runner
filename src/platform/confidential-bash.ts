import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, lstat, readFile, writeFile, rename, rm, rmdir, open } from 'node:fs/promises';
import { join, isAbsolute, normalize } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { StringDecoder } from 'node:string_decoder';
import { SandboxBusyError } from './sandbox-errors.ts';
import { createAgentCapacity } from './agent-capacity.ts';

const outputLimit = 262_144;
const unavailable = () => new Error('Confidential Bash unavailable');
const tenantPattern = /^[a-z0-9][a-z0-9-]{0,79}$/;
const sandboxPattern = /^sure-[a-f0-9-]{36}$/;
const executeFile = promisify(execFile);
export type ConfidentialBashResult = { exitCode: number; output: string; truncated: boolean; timedOut: boolean };

/** The only filesystem passed to untrusted code is its own workspace and the pinned rootfs. */
export function confidentialBashSpec(rootfs: string, workspace: string, timeout: number, id: string) {
  if (!sandboxPattern.test(id)) throw unavailable();
  return {
    ociVersion: '1.0.2', root: { path: rootfs, readonly: true }, hostname: 'workspace',
    hooks: { createRuntime: [{ path: '/usr/local/bin/node', args: ['node', '/opt/sure/scripts/verify-bash-cgroup.ts'],
      env: ['PATH=/usr/local/bin:/usr/bin:/bin'], timeout: 10 }] },
    process: {
      terminal: false, user: { uid: 1000, gid: 1000 }, cwd: '/workspace', noNewPrivileges: true,
      args: ['/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', `${timeout}s`, '/bin/bash', '--noprofile', '--norc', '-s'],
      env: ['PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/workspace', 'LANG=C.UTF-8', 'TMPDIR=/tmp'],
      capabilities: { bounding: [], effective: [], inheritable: [], permitted: [], ambient: [] },
      rlimits: [{ type: 'RLIMIT_NOFILE', hard: 256, soft: 256 }, { type: 'RLIMIT_FSIZE', hard: 16_777_216, soft: 16_777_216 },
        { type: 'RLIMIT_CORE', hard: 0, soft: 0 }],
    },
    mounts: [
      { destination: '/proc', type: 'proc', source: 'proc', options: ['nosuid', 'noexec', 'nodev'] },
      { destination: '/dev', type: 'tmpfs', source: 'tmpfs', options: ['nosuid', 'strictatime', 'mode=755', 'size=65536k'] },
      { destination: '/tmp', type: 'tmpfs', source: 'tmpfs', options: ['nosuid', 'nodev', 'size=67108864', 'mode=1777'] },
      { destination: '/workspace', type: 'bind', source: workspace, options: ['rbind', 'rw', 'nosuid', 'nodev'] },
    ],
    linux: {
      cgroupsPath: '/' + id,
      namespaces: [{ type: 'pid' }, { type: 'network' }, { type: 'ipc' }, { type: 'uts' }, { type: 'mount' }],
      // OCI swap is the combined RAM+swap ceiling; equal values disable swap.
      resources: { memory: { limit: 536_870_912, swap: 536_870_912 }, cpu: { quota: 100_000, period: 100_000 }, pids: { limit: 64 } },
      maskedPaths: ['/proc/acpi', '/proc/kcore', '/proc/keys', '/proc/timer_list', '/proc/scsi', '/sys/firmware'],
      readonlyPaths: ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'],
    },
  };
}

async function privateDirectory(path: string) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || info.uid !== process.getuid?.()) throw unavailable();
}

/** Runs only inside the attested executor. This does not itself prove host confidentiality. */
export function createConfidentialBash(options: { root: string; rootfs: string; runsc: string; concurrency?: number }) {
  for (const path of [options.root, options.rootfs, options.runsc])
    if (!isAbsolute(path) || normalize(path) !== path || path.includes('\0')) throw unavailable();
  const admission = createAgentCapacity(options.concurrency ?? 4, 100);
  const runtime = join(options.root, 'runtime');
  const args = [`--root=${runtime}`, '--platform=systrap', '--network=none'];
  let ownerLease: DatabaseSync | undefined, initialized: Promise<void> | undefined, closed = false;

  async function invoke(extra: string[], input = '', signal?: AbortSignal, timeoutMs = 30_000) {
    return new Promise<{ code: number; stdout: string; stderr: string; truncated: boolean; aborted: boolean }>((resolve, reject) => {
      const child = spawn(options.runsc, [...args, ...extra], {
        env: { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8' }, stdio: ['pipe', 'pipe', 'pipe'],
      });
      let bytes = 0, truncated = false, aborted = false;
      const stdout: Buffer[] = [], stderr: Buffer[] = [];
      const capture = (target: Buffer[]) => (chunk: Buffer) => {
        const remaining = Math.max(0, outputLimit - bytes);
        if (chunk.length > remaining) truncated = true;
        if (remaining) target.push(chunk.subarray(0, remaining));
        bytes += Math.min(remaining, chunk.length);
      };
      child.stdout.on('data', capture(stdout)); child.stderr.on('data', capture(stderr));
      const abort = () => { aborted = true; child.kill('SIGKILL'); };
      const timer = setTimeout(abort, timeoutMs);
      signal?.addEventListener('abort', abort, { once: true });
      child.stdin.on('error', () => {});
      child.once('error', () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(unavailable()); });
      child.once('close', code => {
        clearTimeout(timer); signal?.removeEventListener('abort', abort);
        resolve({ code: code ?? 137, stdout: new StringDecoder('utf8').write(Buffer.concat(stdout)),
          stderr: new StringDecoder('utf8').write(Buffer.concat(stderr)), truncated, aborted });
      });
      if (signal?.aborted) abort(); else child.stdin.end(input);
    });
  }
  async function stop(id: string) {
    if (!sandboxPattern.test(id)) throw unavailable();
    await invoke(['delete', '--force', id]);
    const listed = await invoke(['list', '--format=json']);
    if (listed.aborted || listed.code !== 0) throw unavailable();
    let values: unknown;
    try { values = JSON.parse(listed.stdout); } catch { throw unavailable(); }
    // runsc emits JSON null for an empty inventory.
    if (values !== null && (!Array.isArray(values) || values.some(value => !value || typeof value !== 'object' || !('id' in value) || value.id === id))) throw unavailable();
    // An OOM-killed runtime can leave an empty cgroup after removing its OCI
    // state. Confirm that it contains no live tasks and reclaim that exact leaf.
    const group = '/sys/fs/cgroup/' + id;
    try {
      const events = await readFile(group + '/cgroup.events', 'utf8');
      if (!/^populated 0$/m.test(events)) throw unavailable();
      await rmdir(group);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  async function marker(path: string, id: string) {
    const staging = `${path}.${randomUUID()}`;
    const file = await open(staging, 'wx', 0o600);
    try { await file.writeFile(JSON.stringify({ id })); await file.sync(); } finally { await file.close(); }
    await rename(staging, path);
    const dir = await open(join(path, '..'), 'r'); try { await dir.sync(); } finally { await dir.close(); }
  }
  function initialize() {
    return initialized ??= (async () => {
      await privateDirectory(options.root); await privateDirectory(runtime);
      const path = join(options.root, 'supervisor.sqlite');
      try { const info = await lstat(path); if (!info.isFile() || info.isSymbolicLink()) throw unavailable(); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      ownerLease = new DatabaseSync(path);
      try {
        // One supervisor owns the pool, including its global concurrency bound.
        // Kernel file locks release after a crash; a second live process cannot
        // double capacity or stop the first process's running commands.
        ownerLease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE');
        const listed = await invoke(['list', '--format=json']);
        if (listed.aborted || listed.code !== 0 || listed.truncated) throw unavailable();
        const values: unknown = JSON.parse(listed.stdout);
        if (values !== null) {
          if (!Array.isArray(values) || values.length > 100) throw unavailable();
          for (const value of values) {
            if (!value || typeof value !== 'object' || typeof value.id !== 'string') throw unavailable();
            await stop(value.id);
          }
        }
        // Preserve each tenant's journal: stopped orphan work remains uncertain.
      } catch { ownerLease.close(); ownerLease = undefined; throw unavailable(); }
    })();
  }
  return {
    async close() {
      if (admission.size !== 0) throw unavailable();
      closed = true;
      await initialized;
      ownerLease?.close(); ownerLease = undefined;
    },
    async execute(tenant: string, command: string, timeout: number, signal: AbortSignal = new AbortController().signal): Promise<ConfidentialBashResult> {
      if (!tenantPattern.test(tenant) || !command.trim() || command.includes('\0') || Buffer.byteLength(command) > 16_000
        || !Number.isInteger(timeout) || timeout < 1 || timeout > 60) throw unavailable();
      signal.throwIfAborted();
      if (closed) throw unavailable();
      await initialize();
      signal.throwIfAborted();
      if (closed) throw unavailable();
      const release = await admission.acquire(signal);
      let lease: DatabaseSync | undefined;
      try {
        await privateDirectory(options.root); await privateDirectory(runtime);
        // Bound retained workspaces as well as concurrent processes. Otherwise
        // an issuer could accumulate unbounded tmpfs mounts with distinct ids.
        const tenants = new DatabaseSync(join(options.root, 'tenants.sqlite'));
        try {
          tenants.exec('PRAGMA busy_timeout=0; CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY); BEGIN IMMEDIATE');
          if (!tenants.prepare('SELECT id FROM tenants WHERE id=?').get(tenant)) {
            const count = tenants.prepare('SELECT COUNT(*) AS count FROM tenants').get() as { count: number };
            if (count.count >= 100) throw unavailable();
            tenants.prepare('INSERT INTO tenants(id) VALUES(?)').run(tenant);
          }
          tenants.exec('COMMIT');
        } finally { tenants.close(); }
        const directory = join(options.root, 'tenants', createHash('sha256').update(tenant).digest('hex'));
        await privateDirectory(directory);
        const leasePath = join(directory, 'lease.sqlite');
        try { const info = await lstat(leasePath); if (!info.isFile() || info.isSymbolicLink()) throw unavailable(); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
        lease = new DatabaseSync(leasePath);
        try { lease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE'); }
        catch { throw new SandboxBusyError(); }
        const journal = join(directory, 'execution.json');
        try {
          const prior = JSON.parse(await readFile(journal, 'utf8')) as { id: string };
          await stop(prior.id);
          // An uncertain previous command may have made changes. Never rerun
          // it or silently certify recovery; retain quarantine for the operator.
          throw unavailable();
        } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
        const workspace = join(directory, 'workspace');
        try { await mkdir(workspace, { mode: 0o700 }); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
        const workspaceInfo = await lstat(workspace);
        if (!workspaceInfo.isDirectory() || workspaceInfo.isSymbolicLink()) throw unavailable();
        // A per-tenant tmpfs bounds both bytes and inode exhaustion. It lives
        // across commands, while the runsc process exists only during a call.
        const mounted = await executeFile('/usr/bin/findmnt', ['--mountpoint', workspace, '--noheadings', '--output', 'FSTYPE,OPTIONS']).catch(() => undefined);
        if (!mounted) await executeFile('/usr/bin/mount', ['-t', 'tmpfs', '-o', 'size=67108864,nr_inodes=8192,nosuid,nodev,mode=0700,uid=1000,gid=1000', 'tmpfs', workspace]);
        else {
          const [type, flags] = mounted.stdout.trim().split(/\s+/), values = new Set(flags?.split(','));
          if (type !== 'tmpfs' || !values.has('nosuid') || !values.has('nodev')
            || !values.has('size=65536k') || !values.has('nr_inodes=8192')) throw unavailable();
        }
        // Only the trusted supervisor creates this parent. Untrusted code sees
        // the bind mount contents, never this directory's parent or lease.
        const { chown } = await import('node:fs/promises'); await chown(workspace, 1000, 1000);
        const id = `sure-${randomUUID()}`, bundle = join(directory, id);
        await privateDirectory(bundle);
        await writeFile(join(bundle, 'config.json'), JSON.stringify(confidentialBashSpec(options.rootfs, workspace, timeout, id)), { mode: 0o600 });
        await marker(journal, id);
        let result;
        try { result = await invoke(['run', '--bundle', bundle, id], command, signal, (timeout + 10) * 1000); }
        finally { await stop(id); }
        if (result.aborted || signal.aborted) throw unavailable();
        const timedOut = result.code === 124 || result.code === 137;
        await rm(journal); await rm(bundle, { recursive: true });
        return { exitCode: result.code, output: result.stdout + result.stderr, truncated: result.truncated, timedOut };
      } finally { lease?.close(); release(); }
    },
  };
}
