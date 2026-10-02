import { BLOB_BYTES, base64, bytes, encoder, fromHex, hex, isToken, randomBytes, randomHex, unbase64 } from './encoding';
import { normalizeRelay } from './encoding';
import { post } from './transport';
export const MAX_FILE_BYTES=16*1024*1024;
const CHUNK_BYTES=BLOB_BYTES-16;
export interface FileDescriptor {name:string;mime:string;size:number;key:string;seed:string;nonce:string;context:string;relay:string;chunks:number;}
export interface BlobJob {id:string;token:string;body:string;relay:string;contactId:string;messageId:string;}
async function capability(seed:string,index:number,purpose:string):Promise<string>{
  const key=await crypto.subtle.importKey('raw',bytes(fromHex(seed)),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC',key,bytes(encoder.encode(`securecomm-blob-v1:${purpose}:${index}`)))));
}
function nonceFor(descriptor:FileDescriptor,index:number):Uint8Array{const nonce=new Uint8Array(12);nonce.set(fromHex(descriptor.nonce));new DataView(nonce.buffer).setUint32(8,index);return nonce;}
function aadFor(descriptor:FileDescriptor,index:number):ArrayBuffer{return bytes(encoder.encode(`securecomm-file-v1:${descriptor.context}:${descriptor.size}:${descriptor.chunks}:${index}`));}
export function validateDescriptor(value:unknown):FileDescriptor {
  const d=value as FileDescriptor;
  if(!d||typeof d.name!=='string'||!d.name||encoder.encode(d.name).length>512||typeof d.mime!=='string'||d.mime.length>120||!Number.isSafeInteger(d.size)||d.size<0||d.size>MAX_FILE_BYTES||!isToken(d.key)||!isToken(d.seed)||!isToken(d.context)||typeof d.nonce!=='string'||!/^[a-f0-9]{16}$/.test(d.nonce)||d.chunks!==Math.max(1,Math.ceil(d.size/CHUNK_BYTES)))throw new Error('Anexo inválido.');
  return {...d,relay:normalizeRelay(d.relay)};
}
export async function encryptFile(file:File,relay:string,contactId:string,messageId:string):Promise<{descriptor:FileDescriptor;jobs:BlobJob[]}>{
  if(file.size>MAX_FILE_BYTES||encoder.encode(file.name).length>512||file.type.length>120||!file.name)throw new Error('Anexo inválido ou maior que 16 MiB.');
  const descriptor:FileDescriptor={name:file.name,mime:file.type||'application/octet-stream',size:file.size,key:randomHex(),seed:randomHex(),nonce:hex(randomBytes(8)),context:randomHex(),relay:normalizeRelay(relay),chunks:Math.max(1,Math.ceil(file.size/CHUNK_BYTES))};
  const key=await crypto.subtle.importKey('raw',bytes(fromHex(descriptor.key)),'AES-GCM',false,['encrypt']);
  const jobs:BlobJob[]=[];
  for(let index=0;index<descriptor.chunks;index++){
    const plaintext=randomBytes(CHUNK_BYTES);plaintext.set(new Uint8Array(await file.slice(index*CHUNK_BYTES,(index+1)*CHUNK_BYTES).arrayBuffer()));
    const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv:bytes(nonceFor(descriptor,index)),additionalData:aadFor(descriptor,index)},key,bytes(plaintext));
    jobs.push({id:await capability(descriptor.seed,index,'id'),token:await capability(descriptor.seed,index,'token'),body:base64(new Uint8Array(encrypted)),relay:descriptor.relay,contactId,messageId});
  }
  return {descriptor,jobs};
}
export async function decryptFile(descriptor:FileDescriptor):Promise<Blob>{
  validateDescriptor(descriptor);
  const key=await crypto.subtle.importKey('raw',bytes(fromHex(descriptor.key)),'AES-GCM',false,['decrypt']);
  const parts:ArrayBuffer[]=[];
  for(let index=0;index<descriptor.chunks;index++){
    const response=await post(descriptor.relay,'/v1/blobs/get',{id:await capability(descriptor.seed,index,'id'),token:await capability(descriptor.seed,index,'token')});
    const ciphertext=unbase64(response.body,BLOB_BYTES);if(ciphertext.length!==BLOB_BYTES)throw new Error('Anexo inválido.');
    let plaintext:ArrayBuffer;try{plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(nonceFor(descriptor,index)),additionalData:aadFor(descriptor,index)},key,bytes(ciphertext));}catch{throw new Error('Integridade do anexo inválida.');}
    parts.push(plaintext.slice(0,Math.min(CHUNK_BYTES,descriptor.size-index*CHUNK_BYTES)));
  }
  return new Blob(parts,{type:descriptor.mime});
}
