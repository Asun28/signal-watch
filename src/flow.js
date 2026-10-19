// Workflow driver (Cloudflare Workflows, in the same Worker): every job of a run is one step, and each step has its
// own CPU budget (10 ms on Workers Free). Steps are retried on failure; a resumed run skips completed steps.
import { WorkflowEntrypoint } from 'cloudflare:workers';
import { orchestrate } from './pipeline.js';

const STEP = { retries: { limit: 2, delay: '10 seconds', backoff: 'constant' }, timeout: '5 minutes' };

export class RunFlow extends WorkflowEntrypoint {
  // payload: { mode, now, day, push, owner }
  async run(event, step) {
    const p = event.payload || {};
    const run = { mode: p.mode || 'Run now', now: p.now || Date.parse(event.timestamp), day: p.day || null, push: p.push || null, owner: p.owner || event.instanceId, wait: p.mode === 'Run now' ? 0 : 120000 };
    const out = await orchestrate(this.env, run, (name, fn) => step.do(name, STEP, fn), { parallel: 1 });
    console.log('flow', JSON.stringify({ mode: run.mode, busy: !!out.busy, run: out.run && { id: out.run.id, items: out.run.items, routed: out.run.routed, ms: out.run.ms } }));
    return out;
  }
}

