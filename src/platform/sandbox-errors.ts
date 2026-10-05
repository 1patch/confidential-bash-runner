export class SandboxBusyError extends Error {
  constructor() { super('Sandbox execution rejected (409)'); this.name = 'SandboxBusyError'; }
}
