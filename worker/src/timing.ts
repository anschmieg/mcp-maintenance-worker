import { DurableObject } from 'cloudflare:workers';

type Probe = { delay_seconds:number; due_at:number; completed_at?:number };
export class TimingProbe extends DurableObject {
  async start(seconds:number) {
    await this.ctx.storage.transaction(async tx=>{
      const existing=await tx.get<Probe>('probe');
      if (existing) {
        if (existing.delay_seconds!==seconds) throw new Error('probe ID already used with different delay');
        return;
      }
      const due_at=Date.now()+seconds*1000;
      await tx.put('probe',{delay_seconds:seconds,due_at});
      await tx.setAlarm(due_at);
    });
    return this.status();
  }
  async status() { return (await this.ctx.storage.get<Probe>('probe')) ?? null; }
  async alarm() {
    const probe=await this.ctx.storage.get<Probe>('probe');
    if (probe && !probe.completed_at) await this.ctx.storage.put('probe',{...probe,completed_at:Date.now()});
  }
}
