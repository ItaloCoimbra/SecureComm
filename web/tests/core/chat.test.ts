import 'fake-indexeddb/auto';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
import { ChatClient } from '../../src/core/chat';
import { randomHex } from '../../src/core/encoding';
import { RelayFixture } from './relay-fixture';

let relay:RelayFixture;const opened:ChatClient[]=[];
async function client(name='test-'+randomHex()) {const c=await ChatClient.open({storageName:name});opened.push(c);return c;}
async function pair(){
  const a=await client(),b=await client(); const invite=await a.createInvite('https://relay.test','B');
  const bId=await b.acceptInvite(invite.code,'A'); await b.sync();await a.sync();await b.sync();
  const ac=a.snapshot().contacts[0],bc=b.snapshot().contacts[0];
  expect(ac.fingerprint).toBe(bc.fingerprint);expect(ac.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  await a.verifyContact(ac.id,bc.fingerprint);await b.verifyContact(bId,ac.fingerprint);
  for(let i=0;i<3;i++){await a.sync();await b.sync();}
  expect(a.snapshot().contacts[0].status).toBe('ready');expect(b.snapshot().contacts[0].status).toBe('ready');
  return {a,b,aId:ac.id,bId};
}
beforeEach(()=>{relay=new RelayFixture();vi.stubGlobal('fetch',relay.fetch);});
afterEach(()=>{opened.splice(0).forEach(c=>c.close());vi.unstubAllGlobals();});

describe('local-only per-relationship browser messenger',()=>{
  it('uses single-use invitations and blocks text until both peers verify the transcript',async()=>{
    const a=await client(),b=await client();const invite=await a.createInvite('https://relay.test','B');
    const bId=await b.acceptInvite(invite.code,'A');
    await expect(b.sendText(bId,'not yet')).rejects.toThrow(/verific/i);
    await b.sync();await a.sync();await b.sync();
    expect(a.snapshot().invitations).toHaveLength(0);
    await expect(b.verifyContact(bId,'0'.repeat(64))).rejects.toThrow(/confere/i);
    await a.verifyContact(a.snapshot().contacts[0].id,a.snapshot().contacts[0].fingerprint);await a.sync();await b.sync();
    await expect(a.sendText(a.snapshot().contacts[0].id,'not both')).rejects.toThrow(/verific/i);
    expect(JSON.stringify(relay.traffic)).not.toContain('curve25519');
  });
  it('retries exact ciphertext after reload and only reports encrypted peer receipt as delivered',async()=>{
    const {a,b,aId,bId}=await pair();relay.failSend=true;
    const id=await a.sendText(aId,'private synthetic message');
    await expect(a.sync()).rejects.toThrow();
    expect(a.snapshot().messages.find(m=>m.id===id)?.status).toBe('pending');
    relay.failSend=false;await a.sync();expect(a.snapshot().messages.find(m=>m.id===id)?.status).toBe('sent');
    await b.sync();await a.sync();expect(a.snapshot().messages.find(m=>m.id===id)?.status).toBe('delivered');
    expect(b.snapshot().messages.filter(m=>m.contactId===bId&&m.text==='private synthetic message')).toHaveLength(1);
    const packets=relay.traffic.filter(t=>t.url.endsWith('/send')&&t.data.id===id).map(t=>t.data.body);expect(new Set(packets).size).toBe(1);
    expect(JSON.stringify(relay.traffic)).not.toContain('private synthetic message');
  });
  it('encrypts file content and names before upload and rejects damaged encrypted chunks',async()=>{
    const {a,b,aId,bId}=await pair();const file=new File(['synthetic secret document'],'private-name.txt',{type:'text/plain'});
    const id=await a.sendFile(aId,file);await a.sync();await b.sync();await a.sync();
    const received=b.snapshot().messages.find(m=>m.id===id)!;expect(received.file?.name).toBe(file.name);
    expect(await (await b.downloadFile(bId,id)).text()).toBe('synthetic secret document');
    expect(JSON.stringify(relay.traffic)).not.toContain(file.name);expect(JSON.stringify(relay.traffic)).not.toContain('synthetic secret document');
    for(const blob of relay.blobs.values())blob.body='A'.repeat(blob.body.length-2)+'==';
    await expect(b.downloadFile(bId,id)).rejects.toThrow();
  });
  it('rotates to an independent relay only after authenticated confirmation on the new queue',async()=>{
    const {a,b,aId,bId}=await pair();const old=a.snapshot().contacts[0].relay;
    await a.rotateQueue(aId,'https://second-relay.test');expect(a.snapshot().contacts[0].rotationPending).toBe(true);
    await a.sync();await b.sync();await a.sync();await b.sync();
    expect(a.snapshot().contacts[0].rotationPending).toBe(false);expect(a.snapshot().contacts[0].relay).not.toBe(old);
    const id=await b.sendText(bId,'after rotation');await b.sync();await a.sync();
    expect(a.snapshot().messages.some(m=>m.id===id&&m.text==='after rotation')).toBe(true);
  });
  it('removes contacts and wiping creates an empty nonrecoverable profile',async()=>{
    const {a,b,aId}=await pair();await a.sendText(aId,'history');await a.removeContact(aId);expect(a.snapshot().contacts).toHaveLength(0);expect(a.snapshot().messages).toHaveLength(0);
    await b.wipe();expect(b.snapshot().contacts).toHaveLength(0);expect(b.snapshot().messages).toHaveLength(0);expect(b.snapshot().invitations).toHaveLength(0);
  });
});
