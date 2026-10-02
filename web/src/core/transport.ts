import { isToken, normalizeRelay, randomHex, sha256 } from './encoding';
export interface WriteRoute { relay:string; writeId:string; token:string; }
export interface ReadQueue { relay:string; readId:string; readToken:string; writeId:string; writeToken:string; ttl:number; singleUse:boolean; }
export class RelayError extends Error {constructor(readonly status:number){super(status===429?'Relay sem capacidade; tente novamente mais tarde.':status===403?'Caixa expirada ou acesso recusado. Gere um novo convite se o vínculo foi perdido.':'Relay indisponível ou solicitação recusada.');}}
export function route(queue:ReadQueue):WriteRoute{return{relay:queue.relay,writeId:queue.writeId,token:queue.writeToken};}
export function newQueue(relay:string,singleUse=false):ReadQueue{return{relay:normalizeRelay(relay),readId:randomHex(),readToken:randomHex(),writeId:randomHex(),writeToken:randomHex(),ttl:singleUse?600:2592000,singleUse};}
export function validateRoute(value:unknown):WriteRoute {
  const r=value as WriteRoute;
  if(!r||!isToken(r.writeId)||!isToken(r.token)||typeof r.relay!=='string')throw new Error('Rota de entrega inválida.');
  return {relay:normalizeRelay(r.relay),writeId:r.writeId,token:r.token};
}
export async function post(relay:string,path:string,payload:unknown):Promise<any>{
  let response:Response;
  try{response=await fetch(normalizeRelay(relay)+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:AbortSignal.timeout(15000)});}
  catch{throw new Error('Relay indisponível. As mensagens pendentes continuam salvas neste aparelho.');}
  if(!response.ok)throw new RelayError(response.status);
  const text=await response.text();if(text.length>800000)throw new Error('Resposta do relay excede o limite.');
  try{return JSON.parse(text);}catch{throw new Error('Resposta inválida do relay.');}
}
export async function createQueue(q:ReadQueue):Promise<void>{await post(q.relay,'/v1/queues',{read_id:q.readId,write_id:q.writeId,read_hash:await sha256(q.readToken),write_hash:await sha256(q.writeToken),ttl:q.ttl,single_use:q.singleUse});}
export async function deleteQueue(q:ReadQueue):Promise<void>{try{await post(q.relay,'/v1/delete',{read_id:q.readId,token:q.readToken});}catch(error){if(!(error instanceof RelayError&&error.status===403))throw error;}}
