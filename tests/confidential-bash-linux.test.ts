import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createConfidentialBash } from '../src/platform/confidential-bash.ts';

const enabled = process.env.CONFIDENTIAL_BASH_LINUX_TEST === '1';
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

test('100 real user workspaces execute Bash through bounded gVisor capacity', { skip: !enabled }, async () => {
  const runtime = createConfidentialBash({ root: '/run/sure-bash-density', rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc', concurrency: 4 });
  const started = performance.now();
  const results = await Promise.all(Array.from({ length: 100 }, (_, index) => runtime.execute(`synthetic-${index}`,
    `printf '%s' ${index} > owner; test "$(cat owner)" = ${index}; python3 -c 'print(sum(range(1,1001)))'`, 20)));
  for (const result of results) { assert.equal(result.exitCode, 0, result.output); assert.equal(result.output, '500500\n'); }
  await assert.rejects(runtime.execute('synthetic-101', 'true', 20), /unavailable/);
  console.log(JSON.stringify({ syntheticUsers: 100, bashCompleted: results.length, milliseconds: Math.round(performance.now() - started), confidentialHardware: false }));
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
