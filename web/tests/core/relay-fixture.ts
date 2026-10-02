import { sha256 } from '../../src/core/encoding';

export class RelayFixture {
  queues=new Map<string,any>(); blobs=new Map<string,any>(); traffic:{url:string;data:any}[]=[];
  failSend=false; failAck=false;
  fetch=async(input:RequestInfo|URL,init?:RequestInit):Promise<Response>=>{
    const url=new URL(String(input));const data=JSON.parse(init?.body as string??'{}');this.traffic.push({url:url.href,data:structuredClone(data)});
    if(this.failSend && ['/v1/send','/v1/blobs/put'].includes(url.pathname)) throw new Error('offline');
    if(this.failAck&&url.pathname==='/v1/ack')throw new Error('offline ack');
    const response=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
    const namespace=url.origin;
    if(url.pathname==='/v1/queues') {
      const key=namespace+data.read_id,old=this.queues.get(key);
      if(old&&JSON.stringify(old.config)!==JSON.stringify(data))return response({error:'conflict'},409);
      if(!old)this.queues.set(key,{config:data,items:new Map(),used:undefined});return response({ok:true});
    }
    if(url.pathname.startsWith('/v1/blobs/')){
      const key=namespace+data.id,old=this.blobs.get(key);
      if(url.pathname.endsWith('/put')){if(old&&(old.token!==data.token||old.body!==data.body))return response({error:'conflict'},409);this.blobs.set(key,data);return response({ok:true});}
      if(!old||old.token!==data.token)return response({error:'forbidden'},403);
      if(url.pathname.endsWith('/delete')){this.blobs.delete(key);return response({ok:true});}return response({body:old.body});
    }
    const queue=url.pathname==='/v1/send'?[...this.queues.entries()].find(([key,q])=>key.startsWith(namespace)&&q.config.write_id===data.write_id)?.[1]:this.queues.get(namespace+data.read_id);
    if(!queue||await sha256(data.token)!==(url.pathname==='/v1/send'?queue.config.write_hash:queue.config.read_hash))return response({error:'forbidden'},403);
    if(url.pathname==='/v1/send'){
      if(queue.config.single_use&&queue.used&&queue.used!==data.id)return response({error:'consumed'},409);
      const old=queue.items.get(data.id);if(old&&old!==data.body)return response({error:'conflict'},409);
      queue.used=data.id;queue.items.set(data.id,data.body);return response({ok:true});
    }
    if(url.pathname==='/v1/read')return response({items:[...queue.items.entries()].slice(0,data.limit).map(([id,body])=>({id,body}))});
    if(url.pathname==='/v1/ack'){data.ids.forEach((id:string)=>queue.items.delete(id));return response({ok:true});}
    if(url.pathname==='/v1/delete'){this.queues.delete(namespace+data.read_id);return response({ok:true});}
    return response({error:'notfound'},404);
  };
}
