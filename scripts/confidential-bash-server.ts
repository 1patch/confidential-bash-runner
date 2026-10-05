import { createConfidentialBash } from '../src/platform/confidential-bash.ts';
import { createConfidentialBashServer } from '../src/platform/confidential-bash-server.ts';

// Only the public issuer key belongs in the measured configuration. The private
// signing key belongs to the trusted coordinator, never to tenant Bash.
const bash = createConfidentialBash({ root: '/run/sure-bash', rootfs: '/opt/sure/rootfs', runsc: '/usr/local/bin/runsc' });
const runtime = createConfidentialBashServer({ publicKey: process.env.SURE_BASH_ISSUER_PUBLIC_KEY ?? '', execute: bash.execute });
// Tinfoil's shim reaches this port only on the private container network.
runtime.server.listen(8080, '0.0.0.0');
let stopping = false;
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
  if (stopping) return; stopping = true;
  void runtime.close().then(() => bash.close()).then(() => process.exit(0), () => process.exit(1));
});
