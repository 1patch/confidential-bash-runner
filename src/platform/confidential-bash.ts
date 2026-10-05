import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, lstat, readFile, writeFile, rename, rm, rmdir, open, readdir } from 'node:fs/promises';
import { join, isAbsolute, normalize } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { StringDecoder } from 'node:string_decoder';
import { SandboxBusyError } from './sandbox-errors.ts';
import { createAgentCapacity, AgentCapacityError } from './agent-capacity.ts';

const outputLimit = 262_144;
const unavailable = () => new Error('Confidential Bash unavailable');
const tenantPattern = /^[a-z0-9][a-z0-9-]{0,79}$/;
const sandboxPattern = /^sure-[a-f0-9-]{36}$/;
const executeFile = promisify(execFile);
export const confidentialWorkspaceIdleMs = 10 * 60_000;
const workspaceLimit = 100;
interface WorkspaceRecord { id: string; last_completed: number | null; retiring: number; allocated_at: number | null }
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
export function createConfidentialBash(options: { root: string; rootfs: string; runsc: string; concurrency?: number; now?: () => number }) {
  for (const path of [options.root, options.rootfs, options.runsc])
    if (!isAbsolute(path) || normalize(path) !== path || path.includes('\0')) throw unavailable();
  const admission = createAgentCapacity(options.concurrency ?? 4, 100);
  // Allocation/retirement waits are bounded and separate from running Bash.
  // A tenant lease is never waited for while holding this coordinator.
  const allocation = createAgentCapacity(1, 100, 10_000);
  const runtime = join(options.root, 'runtime');
  const tenantRoot = join(options.root, 'tenants');
  const args = [`--root=${runtime}`, '--platform=systrap', '--network=none'];
  let ownerLease: DatabaseSync | undefined, tenants: DatabaseSync | undefined, initialized: Promise<void> | undefined, closed = false;
  let retirementCursor = 0;
  const now = () => {
    const value = (options.now ?? Date.now)();
    if (!Number.isSafeInteger(value) || value < 0) throw unavailable();
    return value;
  };

  async function privateDatabase(path: string) {
    try { const file = await open(path, 'wx', 0o600); await file.close(); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw unavailable();
    return new DatabaseSync(path);
  }
  const directoryFor = (tenant: string) => join(tenantRoot, createHash('sha256').update(tenant).digest('hex'));
  async function synchronize(directory: string) {
    const file = await open(directory, 'r'); try { await file.sync(); } finally { await file.close(); }
  }
  async function allocated(signal: AbortSignal) {
    try { return await allocation.acquire(signal); }
    catch (error) { if (error instanceof AgentCapacityError) throw new SandboxBusyError(); throw error; }
  }
  function records() {
    const values = tenants!.prepare('SELECT id,last_completed,retiring,allocated_at FROM tenants ORDER BY COALESCE(last_completed,allocated_at),id LIMIT 101').all() as unknown as WorkspaceRecord[];
    if (values.length > workspaceLimit || values.some(value => typeof value.id !== 'string' || !tenantPattern.test(value.id)
      || value.last_completed !== null && (!Number.isSafeInteger(value.last_completed) || value.last_completed < 0)
      || value.allocated_at !== null && (!Number.isSafeInteger(value.allocated_at) || value.allocated_at < 0)
      || ![0, 1].includes(value.retiring))) throw unavailable();
    return values;
  }
  async function workspaceMount(workspace: string) {
    let result;
    try {
      result = await executeFile('/usr/bin/findmnt', ['--json', '--submounts', '--mountpoint', workspace, '--output', 'TARGET,FSTYPE,OPTIONS'],
        { timeout: 5000, maxBuffer: 65_536 });
    } catch (error) {
      const missing = error as { code?: unknown; stdout?: unknown; stderr?: unknown };
      if (missing.code === 1 && missing.stdout === '' && missing.stderr === '') return;
      throw unavailable();
    }
    const value = JSON.parse(result.stdout) as { filesystems?: { target?: unknown; fstype?: unknown; options?: unknown; children?: unknown }[] };
    const mount = value.filesystems?.[0];
    if (value.filesystems?.length !== 1 || !mount || mount.target !== workspace || mount.fstype !== 'tmpfs'
      || typeof mount.options !== 'string' || mount.children !== undefined) throw unavailable();
    const flags = new Set(mount.options.split(','));
    if (!flags.has('nosuid') || !flags.has('nodev') || !flags.has('size=65536k') || !flags.has('nr_inodes=8192')) throw unavailable();
    return mount;
  }
  async function journalAbsent(directory: string) {
    try { await lstat(join(directory, 'execution.json')); return false; }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true; throw error; }
  }
  async function retire(record: WorkspaceRecord, time: number, signal: AbortSignal) {
    const activity = record.last_completed ?? record.allocated_at;
    if (!record.retiring && (activity === null || time < activity || time - activity < confidentialWorkspaceIdleMs)) return false;
    signal.throwIfAborted();
    await privateDirectory(options.root); await privateDirectory(tenantRoot);
    const prepared = record.last_completed === null && record.allocated_at !== null;
    const directory = directoryFor(record.id), workspace = join(directory, 'workspace');
    let lease: DatabaseSync | undefined;
    try {
      const info = await lstat(directory).catch(error => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT' && (record.retiring || prepared)) return undefined;
        throw error;
      });
      // A crash after directory removal may resume only the durable retirement
      // intent; an absent ordinary workspace never becomes a fresh assignment.
      if (!info) {
        tenants!.prepare('UPDATE tenants SET retiring=1 WHERE id=?').run(record.id);
        await synchronize(tenantRoot);
        tenants!.prepare('DELETE FROM tenants WHERE id=? AND retiring=1').run(record.id); return true;
      }
      if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw unavailable();
      if (!await journalAbsent(directory)) return false;
      const names = await readdir(directory);
      // A call can fail before its durable execution journal. With no journal
      // and the tenant lease held, only these exact supervisor-owned preparation
      // artifacts may be reclaimed; an actual interrupted run remains fenced.
      const preparations = names.filter(name => !['workspace', 'lease.sqlite'].includes(name));
      for (const name of preparations) {
        const path = join(directory, name), info = await lstat(path);
        if (sandboxPattern.test(name)) {
          if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw unavailable();
          const entries = await readdir(path);
          if (entries.some(entry => entry !== 'config.json')) throw unavailable();
          if (entries.length) {
            const configuration = await lstat(join(path, 'config.json'));
            if (!configuration.isFile() || configuration.isSymbolicLink() || configuration.uid !== process.getuid?.()
              || (configuration.mode & 0o077) !== 0 || configuration.size > 100_000) throw unavailable();
          }
        } else if (/^execution\.json\.[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(name)) {
          if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0 || info.size > 1024) throw unavailable();
        } else return false;
      }
      lease = await privateDatabase(join(directory, 'lease.sqlite'));
      try { lease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE'); }
      catch (error) {
        if (error && typeof error === 'object' && 'errcode' in error && typeof error.errcode === 'number' && (error.errcode & 0xff) === 5) return false;
        throw error;
      }
      if (!await journalAbsent(directory)) return false;
      const workspaceInfo = await lstat(workspace).catch(error => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT' && (record.retiring || prepared)) return undefined;
        throw error;
      });
      if (workspaceInfo && (!workspaceInfo.isDirectory() || workspaceInfo.isSymbolicLink())) throw unavailable();
      const mounted = workspaceInfo ? await workspaceMount(workspace) : undefined;
      if (!record.retiring && !mounted && !prepared) return false;
      signal.throwIfAborted();
      tenants!.prepare('UPDATE tenants SET retiring=1 WHERE id=?').run(record.id);
      // Once durable intent exists, finish this bounded cleanup even if the
      // requesting call is cancelled. No guest command is dispatched here.
      if (mounted) await executeFile('/usr/bin/umount', ['--', workspace], { timeout: 5000, maxBuffer: 65_536 });
      if (await workspaceMount(workspace)) throw unavailable();
      if (workspaceInfo) await rmdir(workspace); // Never recursively delete guest-controlled contents.
      for (const name of preparations) {
        const path = join(directory, name);
        if (sandboxPattern.test(name)) {
          const entries = await readdir(path);
          if (entries.some(entry => entry !== 'config.json')) throw unavailable();
          if (entries.length) await rm(join(path, 'config.json'));
          await rmdir(path);
        } else await rm(path);
      }
      lease.close(); lease = undefined;
      const remaining = await readdir(directory);
      if (remaining.some(name => name !== 'lease.sqlite')) throw unavailable();
      const leaseInfo = await lstat(join(directory, 'lease.sqlite'));
      if (!leaseInfo.isFile() || leaseInfo.isSymbolicLink() || leaseInfo.uid !== process.getuid?.() || (leaseInfo.mode & 0o077) !== 0) throw unavailable();
      await rm(join(directory, 'lease.sqlite')); await rmdir(directory); await synchronize(tenantRoot);
      tenants!.prepare('DELETE FROM tenants WHERE id=? AND retiring=1').run(record.id);
      return true;
    } finally { lease?.close(); }
  }

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
      await privateDirectory(options.root); await privateDirectory(runtime); await privateDirectory(tenantRoot);
      const path = join(options.root, 'supervisor.sqlite');
      ownerLease = await privateDatabase(path);
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
        tenants = await privateDatabase(join(options.root, 'tenants.sqlite'));
        tenants.exec('PRAGMA busy_timeout=0; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY)');
        const columns = tenants.prepare('PRAGMA table_info(tenants)').all() as unknown as { name: string }[];
        if (columns.length === 1 && columns[0]?.name === 'id') {
          tenants.exec('BEGIN IMMEDIATE; ALTER TABLE tenants ADD COLUMN last_completed INTEGER; ALTER TABLE tenants ADD COLUMN retiring INTEGER NOT NULL DEFAULT 0; ALTER TABLE tenants ADD COLUMN allocated_at INTEGER; COMMIT');
        } else if (columns.map(value => value.name).join(',') === 'id,last_completed,retiring') {
          tenants.exec('ALTER TABLE tenants ADD COLUMN allocated_at INTEGER');
        } else if (columns.map(value => value.name).join(',') !== 'id,last_completed,retiring,allocated_at') throw unavailable();
        records();
      } catch { tenants?.close(); tenants = undefined; ownerLease.close(); ownerLease = undefined; throw unavailable(); }
    })();
  }
  return {
    async close() {
      if (admission.size !== 0 || allocation.size !== 0) throw unavailable();
      closed = true;
      await initialized;
      tenants?.close(); tenants = undefined; ownerLease?.close(); ownerLease = undefined;
    },
    async retireIdle(signal: AbortSignal = new AbortController().signal) {
      signal.throwIfAborted(); if (closed) throw unavailable();
      await initialize(); signal.throwIfAborted(); if (closed) throw unavailable();
      const release = await allocated(signal);
      const report = { checked: 0, retired: 0, retained: 0, failed: 0 };
      try {
        const time = now();
        // Bound each timer slice. At-capacity admission below only needs one
        // successful retirement; neither path scans unbounded historical users.
        const eligible = records().filter(record => {
          const activity = record.last_completed ?? record.allocated_at;
          return record.retiring || activity !== null && time >= activity && time - activity >= confidentialWorkspaceIdleMs;
        });
        const start = eligible.length ? retirementCursor % eligible.length : 0;
        const batch = [...eligible.slice(start), ...eligible.slice(0, start)].slice(0, 8);
        retirementCursor = eligible.length ? (start + batch.length) % eligible.length : 0;
        // Rotate so a group of long-lived quarantines cannot starve every
        // healthy idle workspace that happens to sort after them.
        for (const record of batch) {
          signal.throwIfAborted();
          report.checked++;
          try { if (await retire(record, time, signal)) report.retired++; else report.retained++; }
          catch (error) { if (signal.aborted) throw error; report.failed++; }
        }
        return report;
      } finally { release(); }
    },
    async execute(tenant: string, command: string, timeout: number, signal: AbortSignal = new AbortController().signal): Promise<ConfidentialBashResult> {
      if (!tenantPattern.test(tenant) || !command.trim() || command.includes('\0') || Buffer.byteLength(command) > 16_000
        || !Number.isInteger(timeout) || timeout < 1 || timeout > 60) throw unavailable();
      signal.throwIfAborted();
      if (closed) throw unavailable();
      await initialize();
      signal.throwIfAborted();
      if (closed) throw unavailable();
      let release: () => void;
      try { release = await admission.acquire(signal); }
      catch (error) { if (error instanceof AgentCapacityError) throw new SandboxBusyError(); throw error; }
      let lease: DatabaseSync | undefined;
      let dispatched = false;
      try {
        await privateDirectory(options.root); await privateDirectory(runtime); await privateDirectory(tenantRoot);
        const releaseAllocation = await allocated(signal);
        const directory = directoryFor(tenant);
        try {
          let retained = records(), existing = retained.find(value => value.id === tenant);
          if (existing?.retiring) {
            if (!await retire(existing, now(), signal)) throw unavailable();
            retained = records(); existing = undefined;
          }
          if (!existing) {
            if (retained.length >= workspaceLimit) {
              const time = now(); let retired = false;
              for (const record of retained) {
                signal.throwIfAborted();
                try { if (await retire(record, time, signal)) { retired = true; break; } }
                catch (error) { if (signal.aborted) throw error; /* Retain this exact failed retirement; try another idle owner. */ }
              }
              if (!retired) throw new SandboxBusyError(); // No command has been dispatched.
            }
            signal.throwIfAborted();
            tenants!.prepare('INSERT INTO tenants(id,last_completed,retiring,allocated_at) VALUES(?,NULL,0,?)').run(tenant, now());
          }
          await privateDirectory(directory);
          lease = await privateDatabase(join(directory, 'lease.sqlite'));
          try { lease.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE'); }
          catch (error) {
            if (error && typeof error === 'object' && 'errcode' in error && typeof error.errcode === 'number' && (error.errcode & 0xff) === 5) throw new SandboxBusyError();
            throw error;
          }
        } finally { releaseAllocation(); }
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
        const mounted = await workspaceMount(workspace);
        if (!mounted) await executeFile('/usr/bin/mount', ['-t', 'tmpfs', '-o', 'size=67108864,nr_inodes=8192,nosuid,nodev,mode=0700,uid=1000,gid=1000', 'tmpfs', workspace]);
        await workspaceMount(workspace).then(value => { if (!value) throw unavailable(); });
        // Only the trusted supervisor creates this parent. Untrusted code sees
        // the bind mount contents, never this directory's parent or lease.
        const { chown } = await import('node:fs/promises'); await chown(workspace, 1000, 1000);
        const id = `sure-${randomUUID()}`, bundle = join(directory, id);
        await privateDirectory(bundle);
        await writeFile(join(bundle, 'config.json'), JSON.stringify(confidentialBashSpec(options.rootfs, workspace, timeout, id)), { mode: 0o600 });
        signal.throwIfAborted();
        await marker(journal, id);
        dispatched = true;
        let result;
        try { result = await invoke(['run', '--bundle', bundle, id], command, signal, (timeout + 10) * 1000); }
        finally { await stop(id); }
        if (result.aborted || signal.aborted) throw unavailable();
        const timedOut = result.code === 124 || result.code === 137;
        await rm(bundle, { recursive: true });
        const releaseCompletion = await allocated(new AbortController().signal);
        try {
          const completed = now();
          const update = tenants!.prepare('UPDATE tenants SET last_completed=? WHERE id=? AND retiring=0').run(completed, tenant);
          if (update.changes !== 1) throw unavailable();
          // Update the durable completion clock while the uncertainty journal
          // still fences retirement, then clear it only after confirmed stop.
          await rm(journal); await synchronize(directory);
        } finally { releaseCompletion(); }
        return { exitCode: result.code, output: result.stdout + result.stderr, truncated: result.truncated, timedOut };
      } catch (error) {
        // A cleanup/allocation timeout after the journal was written cannot
        // masquerade as pre-dispatch busy and authorize a command replay.
        if (dispatched && error instanceof SandboxBusyError) throw unavailable();
        throw error;
      } finally { lease?.close(); release(); }
    },
  };
}
