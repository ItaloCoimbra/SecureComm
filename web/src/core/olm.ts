import * as Olm from '@dtelecom/vodozemac-wasm';
export const Account=Olm.Account;
export const Session=Olm.Session;
let initialization:Promise<void>|undefined;
export function initializeOlm():Promise<void>{
  initialization??=(async()=>{const init=(Olm as unknown as {default?:unknown}).default;if(typeof init==='function')await init();})();
  return initialization;
}
