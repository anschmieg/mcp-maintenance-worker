import './wasm_exec.js';
import module from './screen.wasm';

let ready: Promise<void> | undefined;
const g = globalThis as typeof globalThis & {
  Go: new () => { importObject: WebAssembly.Imports; run(wasm: WebAssembly.Instance): Promise<void> };
  maintenanceScreen?: (command: string) => { decision: string; reason: string; syntax_facts: string[]; categories: string[] };
};
export async function classify(command: string) {
  if (new TextEncoder().encode(command).length > 4096) return {decision:'invalid',reason:'command exceeds 4096 bytes',syntax_facts:[],categories:[]};
  ready ??= (async () => {
    const go = new g.Go();
    const wasm = await WebAssembly.instantiate(module, go.importObject);
    void go.run(wasm).then(() => { g.maintenanceScreen = undefined; }).catch(() => { g.maintenanceScreen = undefined; });
    if (!g.maintenanceScreen) throw new Error('Wasm parser did not initialize');
  })();
  await ready;
  if (!g.maintenanceScreen) throw new Error('Wasm parser unavailable');
  return g.maintenanceScreen(command);
}
