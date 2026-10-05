/** Bounded FIFO admission. Waiting work owns no agent process or Bash machine. */
export function createAgentCapacity(concurrency = 4, capacity = 100, waitMs = 600_000) {
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 32
    || !Number.isInteger(capacity) || capacity < concurrency || capacity > 500
    || !Number.isInteger(waitMs) || waitMs < 1 || waitMs > 600_000) throw new Error('Invalid agent capacity');
  type Entry = { start: () => void };
  const waiting: Entry[] = [];
  let active = 0;
  function drain() { while (active < concurrency && waiting.length) waiting.shift()!.start(); }
  return {
    get size() { return active + waiting.length; },
    get available() { return active < concurrency && waiting.length === 0; },
    acquire(signal: AbortSignal, background = false): Promise<() => void> {
      signal.throwIfAborted();
      if (active + waiting.length >= capacity || background && (active >= concurrency || waiting.length))
        return Promise.reject(new AgentCapacityError());
      return new Promise((resolve, reject) => {
        let settled = false;
        const cleanup = () => { clearTimeout(timer); signal.removeEventListener('abort', abort); };
        const cancel = (reason: unknown) => {
          if (settled) return;
          settled = true; cleanup();
          const index = waiting.indexOf(entry); if (index !== -1) waiting.splice(index, 1);
          reject(reason); drain();
        };
        const abort = () => cancel(signal.reason);
        const entry: Entry = { start() {
          if (settled) return;
          if (signal.aborted) { abort(); return; }
          settled = true; cleanup(); active++;
          let released = false;
          resolve(() => { if (!released) { released = true; active--; drain(); } });
        } };
        const timer = setTimeout(() => cancel(new AgentCapacityError()), waitMs);
        signal.addEventListener('abort', abort, { once: true });
        waiting.push(entry); drain();
      });
    },
  };
}

export class AgentCapacityError extends Error {
  constructor() { super('Agent capacity unavailable'); }
}
