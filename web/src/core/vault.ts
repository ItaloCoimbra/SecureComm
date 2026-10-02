import { bytes, decoder, encoder, randomBytes } from './encoding';

interface Stored { key:CryptoKey; revision:number; nonce:Uint8Array; ciphertext:ArrayBuffer; }
const localLocks=new Map<string,Promise<unknown>>();
const MAX_STATE_BYTES=24*1024*1024;
const aad=encoder.encode('securecomm-local-vault-v1');
const request=<T>(r:IDBRequest<T>):Promise<T>=>new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Não foi possível ler o armazenamento local.'));});
const done=(tx:IDBTransaction):Promise<void>=>new Promise((resolve,reject)=>{tx.oncomplete=()=>resolve();tx.onabort=tx.onerror=()=>reject(new Error('Falha ao persistir no armazenamento local.'));});

/** Storage encryption is not protection against hostile same-origin JavaScript. */
export class LocalVault<T> {
  private revision=-1;
  private key!:CryptoKey;
  private constructor(private db:IDBDatabase,readonly name:string) {}
  static async open<T>(name:string,initial:()=>T):Promise<LocalVault<T>> {
    if(!name || name.length>160) throw new Error('Nome de armazenamento inválido.');
    const r=indexedDB.open(name,1);
    r.onupgradeneeded=()=>{r.result.createObjectStore('vault');};
    const db=await request(r); db.onversionchange=()=>db.close();
    const vault=new LocalVault<T>(db,name);
    await vault.lock(async()=>{
      const existing=await vault.read();
      if(!existing){
        const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
        const nonce=randomBytes(12),ciphertext=await vault.encrypt(initial(),key,nonce);
        const tx=db.transaction('vault','readwrite');const completed=done(tx);const store=tx.objectStore('vault');
        const current=store.get('profile');current.onsuccess=()=>{if(!current.result) store.put({key,nonce,ciphertext,revision:0},'profile');};
        await completed;
      }
      await vault.load();
    });
    return vault;
  }
  private read():Promise<Stored|undefined>{return request(this.db.transaction('vault').objectStore('vault').get('profile'));}
  private async encrypt(state:T,key:CryptoKey,nonce:Uint8Array):Promise<ArrayBuffer>{
    const raw=encoder.encode(JSON.stringify(state));if(raw.length>MAX_STATE_BYTES) throw new Error('Armazenamento local cheio; remova conversas antigas.');
    return crypto.subtle.encrypt({name:'AES-GCM',iv:bytes(nonce),additionalData:bytes(aad)},key,bytes(raw));
  }
  async load():Promise<T>{
    const stored=await this.read();if(!stored) throw new Error('Estado local perdido. Abra um novo perfil.');
    this.key=stored.key;this.revision=stored.revision;
    try {return JSON.parse(decoder.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(stored.nonce),additionalData:bytes(aad)},stored.key,stored.ciphertext)));}
    catch {throw new Error('Estado local corrompido ou chave perdida. Não existe recuperação.');}
  }
  async save(state:T):Promise<void>{
    const expected=this.revision,nonce=randomBytes(12),ciphertext=await this.encrypt(state,this.key,nonce);
    const tx=this.db.transaction('vault','readwrite'),completed=done(tx),store=tx.objectStore('vault');let conflict=false;
    const r=store.get('profile');r.onsuccess=()=>{const current=r.result as Stored|undefined;if(!current||current.revision!==expected){conflict=true;tx.abort();return;}store.put({key:this.key,revision:expected+1,nonce,ciphertext},'profile');};
    try {await completed;}catch(error){if(conflict)throw new Error('Estado alterado por outra aba. Tente novamente.');throw error;}
    this.revision=expected+1;
  }
  async lock<R>(operation:()=>Promise<R>):Promise<R>{
    const previous=localLocks.get(this.name)??Promise.resolve();
    const run=previous.catch(()=>undefined).then(async()=>{
      if(typeof navigator!=='undefined'&&navigator.locks) return navigator.locks.request('securecomm:'+this.name,operation);
      return operation();
    });
    localLocks.set(this.name,run);
    try{return await run;}finally{if(localLocks.get(this.name)===run)localLocks.delete(this.name);}
  }
  async reset(initial:T):Promise<void>{
    const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    const nonce=randomBytes(12),ciphertext=await this.encrypt(initial,key,nonce),expected=this.revision;
    const tx=this.db.transaction('vault','readwrite'),completed=done(tx),store=tx.objectStore('vault');
    const r=store.get('profile');r.onsuccess=()=>{if(r.result?.revision!==expected){tx.abort();return;}store.clear();store.put({key,nonce,ciphertext,revision:expected+1},'profile');};
    await completed;this.key=key;this.revision=expected+1;
  }
  close():void{this.db.close();}
}
