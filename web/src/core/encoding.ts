export const PACKET_BYTES = 32768;
export const BLOB_BYTES = 65536;
export const encoder = new TextEncoder();
export const decoder = new TextDecoder('utf-8', { fatal:true });
export const bytes = (value: Uint8Array): ArrayBuffer => value.slice().buffer as ArrayBuffer;
export const randomBytes = (size:number): Uint8Array => crypto.getRandomValues(new Uint8Array(size));
export const hex = (value:Uint8Array):string => Array.from(value,b=>b.toString(16).padStart(2,'0')).join('');
export const randomHex = ():string => hex(randomBytes(32));
export const isToken = (value:unknown):value is string => typeof value==='string' && /^[a-f0-9]{64}$/.test(value);
export function fromHex(value:string):Uint8Array {
  if (!/^(?:[a-f0-9]{2})+$/.test(value)) throw new Error('Valor criptográfico inválido.');
  return Uint8Array.from(value.match(/../g)!,v=>parseInt(v,16));
}
export function base64(value:Uint8Array):string {
  let result=''; for(let i=0;i<value.length;i+=8192) result+=String.fromCharCode(...value.subarray(i,i+8192));
  return btoa(result);
}
export function unbase64(value:string, maximum=100000):Uint8Array {
  if(typeof value!=='string'||value.length>Math.ceil(maximum/3)*4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('Pacote inválido.');
  const out=Uint8Array.from(atob(value),c=>c.charCodeAt(0));
  if(out.length>maximum || base64(out)!==value) throw new Error('Pacote inválido.');
  return out;
}
export async function sha256(value:string|Uint8Array):Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(typeof value==='string'?encoder.encode(value):value))));
}
export function encodePacket(value:unknown):string {
  const body=encoder.encode(JSON.stringify(value));
  if(body.length>PACKET_BYTES-4) throw new Error('Mensagem excede o limite.');
  const packet=randomBytes(PACKET_BYTES); new DataView(packet.buffer).setUint32(0,body.length); packet.set(body,4); return base64(packet);
}
export function decodePacket(value:string):unknown {
  const packet=unbase64(value,PACKET_BYTES);
  if(packet.length!==PACKET_BYTES) throw new Error('Pacote inválido.');
  const length=new DataView(packet.buffer).getUint32(0);
  if(length>PACKET_BYTES-4) throw new Error('Pacote inválido.');
  return JSON.parse(decoder.decode(packet.subarray(4,4+length)));
}
export function normalizeRelay(value:string):string {
  let url:URL; try {url=new URL(value);} catch {throw new Error('Endereço de relay inválido.');}
  const loopback=['127.0.0.1','localhost','[::1]'].includes(url.hostname);
  if((url.protocol!=='https:'&&!(url.protocol==='http:'&&loopback)) || url.username||url.password||url.search||url.hash||url.pathname!=='/') throw new Error('Use HTTPS ou HTTP apenas em loopback local.');
  return url.origin;
}
