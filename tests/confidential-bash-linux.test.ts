import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, mkdir, rmdir, symlink, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createConfidentialBash, confidentialWorkspaceIdleMs } from '../src/platform/confidential-bash.ts';
import { SandboxBusyError } from '../src/platform/sandbox-errors.ts';

const enabled = process.env.CONFIDENTIAL_BASH_LINUX_TEST === '1';
const directoryFor = (root: string, tenant: string) => root + '/tenants/' + createHash('sha256').update(tenant).digest('hex');
const executeFile = promisify(execFile);
async function waitForFile(path: string, expected: string) {
  for (let i = 0; i < 250; i++) {
    if (await readFile(path, 'utf8').catch(() => '') === expected) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('The synthetic command must start real Bash before this probe');
}
test('real gVisor Bash separates tenants, supervisor secrets, processes and network', { skip: !enabled }, async () => {
  const existingGroups = new Set(await readdir('/sys/fs/cgroup'));
  const runtime = createConfidentialBash({ root: '/run/sure-bash-test', rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc' });
  await writeFile('/run/sure-supervisor-secret', 'synthetic-supervisor-secret');
  const first = await runtime.execute('synthetic-one', 'printf tenant-one > saved; printf "%s" "$HOME"; id -u; python3 -c "print(sum(range(1,1001)))"', 20);
  assert.equal(first.exitCode, 0, first.output);
  assert.match(first.output, /\/workspace1000\n500500/);
  const second = await runtime.execute('synthetic-two', 'test ! -e saved && test ! -e /run/sure-supervisor-secret && test ! -e /run/sure-bash-test; printf isolated', 20);
  assert.equal(second.exitCode, 0, second.output); assert.match(second.output, /isolated/);
  assert.equal((await runtime.execute('synthetic-one', 'cat saved', 20)).output, 'tenant-one');
  const network = await runtime.execute('synthetic-one', 'python3 - <<\'PY\'\nimport socket\nfor host in ["1.1.1.1", "169.254.169.254", "127.0.0.1"]:\n try:\n  socket.create_connection((host, 80), timeout=.2)\n  raise RuntimeError("network unexpectedly reachable")\n except OSError:\n  pass\nprint("network isolated")\nPY', 20);
  assert.equal(network.exitCode, 0, network.output); assert.match(network.output, /network isolated/);
  const limited = await runtime.execute('synthetic-one', "python3 -c 'print(chr(120)*400000)'", 20);
  assert.equal(limited.exitCode, 0, limited.output.slice(0, 500));
  assert.equal(limited.truncated, true); assert.ok(Buffer.byteLength(limited.output) <= 262_144);
  const failure = await runtime.execute('synthetic-one', 'exit 7', 20); assert.equal(failure.exitCode, 7);
  const timeout = await runtime.execute('synthetic-one', '(sleep 3; printf escaped > late) & sleep 10', 1);
  assert.equal(timeout.timedOut, true);
  await new Promise(resolve => setTimeout(resolve, 3200));
  const clean = await runtime.execute('synthetic-one', 'test ! -e late && cat saved', 20);
  assert.equal(clean.exitCode, 0); assert.equal(clean.output, 'tenant-one');
  // calloc can reserve zero pages lazily on amd64. Touch every page so the test
  // measures actual resident usage, not a permitted virtual address reservation.
  const memory = await runtime.execute('synthetic-one', "python3 -c 'a=bytearray(700*1024*1024); a[::4096]=b\"x\"*len(a[::4096]); print(len(a))'", 10);
  assert.notEqual(memory.exitCode, 0, 'A sandbox must not allocate above its 512 MiB limit');
  const disk = await runtime.execute('synthetic-one', 'for i in 1 2 3 4 5; do dd if=/dev/zero of=/workspace/quota-$i bs=1M count=15 status=none || exit 9; done', 20);
  assert.notEqual(disk.exitCode, 0, 'A workspace must not exceed 64 MiB');
  assert.equal((await runtime.execute('synthetic-one', 'rm -f quota-*; test ! -w /etc/passwd; test ! -w /usr/bin/bash', 20)).exitCode, 0);
  const controller = new AbortController();
  const cancelled = runtime.execute('synthetic-abort', '(sleep 3; printf escaped > late) & printf started > started; sleep 30', 40, controller.signal);
  const directory = '/run/sure-bash-test/tenants/' + createHash('sha256').update('synthetic-abort').digest('hex') + '/workspace';
  let started = false;
  for (let i = 0; i < 100; i++) {
    if (await readFile(directory + '/started', 'utf8').catch(() => '') === 'started') { started = true; break; }
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  controller.abort(); await assert.rejects(cancelled); assert(started, 'Cancellation probe must first execute real Bash');
  await new Promise(resolve => setTimeout(resolve, 3200));
  assert.equal(await readFile(directory + '/late', 'utf8').catch(() => undefined), undefined);
  await assert.rejects(runtime.execute('synthetic-abort', 'echo replay', 20), /unavailable/);
  assert.equal(await readFile('/run/sure-supervisor-secret', 'utf8'), 'synthetic-supervisor-secret');
  assert.deepEqual((await readdir('/sys/fs/cgroup')).filter(name => name.startsWith('sure-') && !existingGroups.has(name)), []);
  await runtime.close();
});

test('100 retained workspaces admit the 101st and later users after safe idle retirement', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-density'; let time = 1_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', concurrency: 4, now: () => time });
  const started = performance.now();
  const results = await Promise.all(Array.from({ length: 100 }, (_, index) => runtime.execute(`synthetic-${index}`,
    `printf '%s' ${index} > owner; test "$(cat owner)" = ${index}; python3 -c 'print(sum(range(1,1001)))'`, 20)));
  for (const result of results) { assert.equal(result.exitCode, 0, result.output); assert.equal(result.output, '500500\n'); }
  await assert.rejects(runtime.execute('synthetic-101', 'printf must-not-run', 20), SandboxBusyError);
  assert.equal(await lstat(directoryFor(root, 'synthetic-101')).catch(() => undefined), undefined);
  time += confidentialWorkspaceIdleMs - 1;
  await assert.rejects(runtime.execute('synthetic-101', 'printf must-not-run', 20), SandboxBusyError);
  time++;
  const next = await runtime.execute('synthetic-101', 'test ! -e owner; printf new-owner > owner; printf isolated', 20);
  assert.equal(next.exitCode, 0, next.output); assert.equal(next.output, 'isolated');
  assert.equal(await lstat(directoryFor(root, 'synthetic-0')).catch(() => undefined), undefined);
  for (let index = 102; index <= 120; index++) {
    const result = await runtime.execute(`synthetic-${index}`, `test ! -e owner; printf '%s' ${index} > owner; cat owner`, 20);
    assert.equal(result.exitCode, 0, result.output); assert.equal(result.output, String(index));
  }
  const returned = await runtime.execute('synthetic-0', 'test ! -e owner; printf empty', 20);
  assert.equal(returned.exitCode, 0, returned.output); assert.equal(returned.output, 'empty');
  const ledger = new DatabaseSync(root + '/tenants.sqlite');
  try { assert.equal((ledger.prepare('SELECT COUNT(*) AS count FROM tenants').get() as { count: number }).count, 100); }
  finally { ledger.close(); }
  assert.equal((await readdir(root + '/tenants')).length, 100);
  console.log(JSON.stringify({ syntheticUsers: 120, bashCompleted: results.length + 21, retainedWorkspaces: 100,
    idleRetirement: true, milliseconds: Math.round(performance.now() - started), confidentialHardware: false }));
  await runtime.close();
});

test('idle retirement preserves active, leased and cancelled uncertain owners and never follows workspace symlinks', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-retirement'; let time = 2_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', now: () => time });
  const guard = '/run/sure-retirement-guard'; await mkdir(guard, { mode: 0o700 });
  await writeFile(guard + '/secret', 'synthetic-guard');
  for (const tenant of ['synthetic-idle', 'synthetic-cancelled', 'synthetic-active', 'synthetic-leased']) {
    assert.equal((await runtime.execute(tenant, 'printf private > saved', 20)).exitCode, 0);
  }
  await symlink(guard, directoryFor(root, 'synthetic-idle') + '/workspace/outside');
  const controller = new AbortController();
  const cancelled = runtime.execute('synthetic-cancelled', 'printf started > started; sleep 30', 40, controller.signal);
  await waitForFile(directoryFor(root, 'synthetic-cancelled') + '/workspace/started', 'started');
  controller.abort(); await assert.rejects(cancelled);
  const externalLease = new DatabaseSync(directoryFor(root, 'synthetic-leased') + '/lease.sqlite');
  externalLease.exec('BEGIN IMMEDIATE');
  const active = runtime.execute('synthetic-active', 'printf started > started; sleep 5; cat saved', 20);
  await waitForFile(directoryFor(root, 'synthetic-active') + '/workspace/started', 'started');
  time += confidentialWorkspaceIdleMs;
  try {
    assert.deepEqual(await runtime.retireIdle(), { checked: 4, retired: 1, retained: 3, failed: 0 });
    assert.equal(await lstat(directoryFor(root, 'synthetic-idle')).catch(() => undefined), undefined);
    assert.equal(await readFile(guard + '/secret', 'utf8'), 'synthetic-guard');
    assert.equal(await readFile(directoryFor(root, 'synthetic-leased') + '/workspace/saved', 'utf8'), 'private');
    assert(await lstat(directoryFor(root, 'synthetic-cancelled') + '/execution.json'));
    assert.equal(await readFile(directoryFor(root, 'synthetic-active') + '/workspace/saved', 'utf8'), 'private');
  } finally { externalLease.close(); }
  const completed = await active; assert.equal(completed.exitCode, 0, completed.output); assert.equal(completed.output, 'private');
  assert.deepEqual(await runtime.retireIdle(), { checked: 2, retired: 1, retained: 1, failed: 0 });
  assert(await lstat(directoryFor(root, 'synthetic-active') + '/workspace'));
  time += confidentialWorkspaceIdleMs;
  assert.deepEqual(await runtime.retireIdle(), { checked: 2, retired: 1, retained: 1, failed: 0 });
  const returned = await runtime.execute('synthetic-active', 'test ! -e saved; printf fresh', 20);
  assert.equal(returned.exitCode, 0, returned.output); assert.equal(returned.output, 'fresh');
  await assert.rejects(runtime.execute('synthetic-cancelled', 'printf replay', 20), /unavailable/);
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(runtime.retireIdle(aborted.signal));
  assert.equal(await readFile(guard + '/secret', 'utf8'), 'synthetic-guard');
  await runtime.close();
});

test('failed unmount retains durable retirement and blocks Bash until the exact tmpfs is reclaimed', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-retirement-busy'; let time = 3_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', now: () => time });
  const tenant = 'synthetic-busy', directory = directoryFor(root, tenant), workspace = directory + '/workspace';
  assert.equal((await runtime.execute(tenant, 'printf old-private > saved', 20)).exitCode, 0);
  const child = spawn('/bin/sleep', ['30'], { cwd: workspace, stdio: 'ignore' });
  const exited = once(child, 'exit'); await once(child, 'spawn');
  time += confidentialWorkspaceIdleMs;
  try {
    assert.deepEqual(await runtime.retireIdle(), { checked: 1, retired: 0, retained: 0, failed: 1 });
    const ledger = new DatabaseSync(root + '/tenants.sqlite');
    try { assert.equal((ledger.prepare('SELECT retiring FROM tenants WHERE id=?').get(tenant) as { retiring: number }).retiring, 1); }
    finally { ledger.close(); }
    assert.equal(await readFile(workspace + '/saved', 'utf8'), 'old-private');
    await assert.rejects(runtime.execute(tenant, 'printf must-not-run > after', 20));
    assert.equal(await lstat(workspace + '/after').catch(() => undefined), undefined);
  } finally { child.kill('SIGKILL'); await exited; }
  assert.deepEqual(await runtime.retireIdle(), { checked: 1, retired: 1, retained: 0, failed: 0 });
  const fresh = await runtime.execute(tenant, 'test ! -e saved; printf empty', 20);
  assert.equal(fresh.exitCode, 0, fresh.output); assert.equal(fresh.output, 'empty');
  await runtime.close();
});

test('cancellation before the execution marker cannot reserve a workspace forever', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-retirement-preparation'; let time = 3_500_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', now: () => time });
  const tenant = 'synthetic-preparation', directory = directoryFor(root, tenant);
  const controller = new AbortController(); let checks = 0;
  const check = controller.signal.throwIfAborted.bind(controller.signal);
  // The sixth native cancellation checkpoint is immediately before the
  // execution marker, after real workspace mounting and bundle preparation.
  Object.defineProperty(controller.signal, 'throwIfAborted', { value() { if (++checks === 6) controller.abort(); check(); } });
  await assert.rejects(runtime.execute(tenant, 'printf must-not-run > executed', 20, controller.signal));
  assert.equal(checks, 6);
  assert.equal(await lstat(directory + '/execution.json').catch(() => undefined), undefined);
  assert.equal(await lstat(directory + '/workspace/executed').catch(() => undefined), undefined);
  assert((await readdir(directory)).some(name => /^sure-/.test(name)), 'The cancellation must occur after preparing a real bundle');
  time += confidentialWorkspaceIdleMs - 1;
  assert.deepEqual(await runtime.retireIdle(), { checked: 0, retired: 0, retained: 0, failed: 0 });
  time++;
  assert.deepEqual(await runtime.retireIdle(), { checked: 1, retired: 1, retained: 0, failed: 0 });
  assert.equal(await lstat(directory).catch(() => undefined), undefined);
  const ledger = new DatabaseSync(root + '/tenants.sqlite');
  try { assert.equal((ledger.prepare('SELECT COUNT(*) AS count FROM tenants').get() as { count: number }).count, 0); }
  finally { ledger.close(); }
  const fresh = await runtime.execute(tenant, 'test ! -e executed; printf fresh', 20);
  assert.equal(fresh.exitCode, 0, fresh.output); assert.equal(fresh.output, 'fresh');
  const existingController = new AbortController(); let existingChecks = 0;
  const existingCheck = existingController.signal.throwIfAborted.bind(existingController.signal);
  Object.defineProperty(existingController.signal, 'throwIfAborted', { value() { if (++existingChecks === 5) existingController.abort(); existingCheck(); } });
  await assert.rejects(runtime.execute(tenant, 'printf must-not-run > after', 20, existingController.signal));
  assert.equal(existingChecks, 5);
  assert.equal(await lstat(directory + '/execution.json').catch(() => undefined), undefined);
  assert.equal(await lstat(directory + '/workspace/after').catch(() => undefined), undefined);
  assert((await readdir(directory)).some(name => /^sure-/.test(name)));
  time += confidentialWorkspaceIdleMs;
  assert.deepEqual(await runtime.retireIdle(), { checked: 1, retired: 1, retained: 0, failed: 0 });
  assert.equal(await lstat(directory).catch(() => undefined), undefined);
  await runtime.close();
});

test('a replaced workspace mountpoint is never followed or recursively cleaned', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-retirement-symlink'; let time = 4_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', now: () => time });
  const tenant = 'synthetic-symlink', workspace = directoryFor(root, tenant) + '/workspace';
  assert.equal((await runtime.execute(tenant, 'printf private > saved', 20)).exitCode, 0);
  const guard = '/run/sure-retirement-symlink-guard'; await mkdir(guard, { mode: 0o700 });
  await writeFile(guard + '/secret', 'synthetic-guard');
  await executeFile('/usr/bin/umount', ['--', workspace]); await rmdir(workspace); await symlink(guard, workspace);
  time += confidentialWorkspaceIdleMs;
  assert.deepEqual(await runtime.retireIdle(), { checked: 1, retired: 0, retained: 0, failed: 1 });
  assert.equal(await readFile(guard + '/secret', 'utf8'), 'synthetic-guard');
  await assert.rejects(runtime.execute(tenant, 'printf must-not-run', 20));
  assert.equal((await lstat(workspace)).isSymbolicLink(), true);
  await rm(workspace); await runtime.close();
});

test('bounded retirement slices rotate past quarantined owners without evicting them', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-retirement-fairness'; let time = 5_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', now: () => time });
  for (let index = 0; index < 9; index++) {
    const tenant = `synthetic-quarantine-${index}`;
    assert.equal((await runtime.execute(tenant, 'printf retained > saved', 20)).exitCode, 0);
    const controller = new AbortController();
    const pending = runtime.execute(tenant, 'printf started > started; sleep 30', 40, controller.signal);
    await waitForFile(directoryFor(root, tenant) + '/workspace/started', 'started');
    controller.abort(); await assert.rejects(pending);
  }
  assert.equal((await runtime.execute('synthetic-zready', 'printf private > saved', 20)).exitCode, 0);
  time += confidentialWorkspaceIdleMs;
  assert.deepEqual(await runtime.retireIdle(), { checked: 8, retired: 0, retained: 8, failed: 0 });
  assert.deepEqual(await runtime.retireIdle(), { checked: 8, retired: 1, retained: 7, failed: 0 });
  assert.equal(await lstat(directoryFor(root, 'synthetic-zready')).catch(() => undefined), undefined);
  for (let index = 0; index < 9; index++) {
    const directory = directoryFor(root, `synthetic-quarantine-${index}`);
    assert(await lstat(directory + '/execution.json'));
    assert.equal(await readFile(directory + '/workspace/saved', 'utf8'), 'retained');
  }
  await runtime.close();
});

test('a queued command rechecks signed authority before creating a dispatch journal', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-expired-authority'; let time = 6_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', concurrency: 1, now: () => time });
  const active = runtime.execute('synthetic-active-authority', 'printf started > started; sleep 2; printf complete', 20);
  await waitForFile(directoryFor(root, 'synthetic-active-authority') + '/workspace/started', 'started');
  let beforeDispatchCalls = 0;
  const tenant = 'synthetic-expired-authority', directory = directoryFor(root, tenant);
  const pending = runtime.execute(tenant, 'printf must-not-run > executed', 20, new AbortController().signal, () => {
    beforeDispatchCalls++;
    // The server supplies this finite failure when its already verified grant
    // expires during the admission wait. This fixture exercises actual gVisor
    // admission and preparation rather than executing an expired command.
    throw new SandboxBusyError();
  });
  const rejected = assert.rejects(pending, SandboxBusyError);
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.equal(beforeDispatchCalls, 0, 'Authority must be checked after the queued call is admitted');
  assert.equal(await lstat(directory).catch(() => undefined), undefined);
  const completed = await active; assert.equal(completed.exitCode, 0, completed.output); assert.equal(completed.output, 'complete');
  await rejected;
  assert.equal(beforeDispatchCalls, 1);
  assert.equal(await lstat(directory + '/execution.json').catch(() => undefined), undefined);
  assert.equal(await lstat(directory + '/workspace/executed').catch(() => undefined), undefined);
  assert((await readdir(directory)).some(name => /^sure-/.test(name)), 'The rejection must occur after preparing the workspace');
  time += confidentialWorkspaceIdleMs;
  assert.deepEqual(await runtime.retireIdle(), { checked: 2, retired: 2, retained: 0, failed: 0 });
  const ledger = new DatabaseSync(root + '/tenants.sqlite');
  try { assert.equal((ledger.prepare('SELECT COUNT(*) AS count FROM tenants').get() as { count: number }).count, 0); }
  finally { ledger.close(); }
  assert.equal((await runtime.execute(tenant, 'test ! -e executed; printf fresh', 20, new AbortController().signal,
    () => { beforeDispatchCalls++; })).output, 'fresh');
  assert.equal(beforeDispatchCalls, 3, 'Fresh authority is checked before journaling and immediately before dispatch');
  await runtime.close();
});

test('authority expiring during dispatch journaling stays quarantined and never returns safe busy', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-expired-journaling'; let time = 7_000_000;
  const runtime = createConfidentialBash({ root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', now: () => time });
  const tenant = 'synthetic-expired-journaling', directory = directoryFor(root, tenant);
  let checks = 0;
  await assert.rejects(runtime.execute(tenant, 'printf must-not-run > executed', 20, new AbortController().signal, () => {
    if (++checks === 2) throw new SandboxBusyError();
  }), error => error instanceof Error && !(error instanceof SandboxBusyError) && /unavailable/.test(error.message));
  assert.equal(checks, 2);
  assert.equal(await lstat(directory + '/workspace/executed').catch(() => undefined), undefined);
  const journal = await readFile(directory + '/execution.json', 'utf8');
  assert.match(JSON.parse(journal).id, /^sure-/);
  time += confidentialWorkspaceIdleMs;
  assert.deepEqual(await runtime.retireIdle(), { checked: 1, retired: 0, retained: 1, failed: 0 });
  assert.equal(await readFile(directory + '/execution.json', 'utf8'), journal);
  await assert.rejects(runtime.execute(tenant, 'printf replay > executed', 20), /unavailable/);
  assert.equal(await lstat(directory + '/workspace/executed').catch(() => undefined), undefined);
  assert.equal(await readFile(directory + '/execution.json', 'utf8'), journal);
  await runtime.close();
});

test('a crashed supervisor is fenced and its orphaned Bash is stopped before accepting another tenant', { skip: !enabled }, async () => {
  const root = '/run/sure-bash-crash', tenant = 'synthetic-crash';
  const workspace = root + '/tenants/' + createHash('sha256').update(tenant).digest('hex') + '/workspace';
  const options = { root, rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc' };
  const source = `import {createConfidentialBash} from ${JSON.stringify(new URL('../src/platform/confidential-bash.ts', import.meta.url).href)};
    await createConfidentialBash(${JSON.stringify(options)}).execute('synthetic-crash', 'printf started > started; (sleep 5; printf escaped > late) & sleep 30', 40);`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: 'ignore', env: { PATH: '/usr/local/bin:/usr/bin:/bin' } });
  const exited = once(child, 'exit');
  try {
    let started = false;
    for (let i = 0; i < 250; i++) {
      if (await readFile(workspace + '/started', 'utf8').catch(() => '') === 'started') { started = true; break; }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert(started, 'The old supervisor must start real Bash before being killed');
    const competing = createConfidentialBash(options);
    await assert.rejects(competing.execute('synthetic-new', 'true', 20), /unavailable/);
    child.kill('SIGKILL'); await exited;
    const restarted = createConfidentialBash(options);
    try {
      assert.equal((await restarted.execute('synthetic-new', 'printf recovered', 20)).output, 'recovered');
      await new Promise(resolve => setTimeout(resolve, 5200));
      assert.equal(await readFile(workspace + '/late', 'utf8').catch(() => undefined), undefined);
      await assert.rejects(restarted.execute(tenant, 'echo replay', 20), /unavailable/);
    } finally { await restarted.close(); }
  } finally { child.kill('SIGKILL'); await exited; }
});
