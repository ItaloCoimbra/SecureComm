import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { Account, Session } from '@dtelecom/vodozemac-wasm';
import { decodePacket, encodePacket, randomHex, normalizeRelay } from '../../src/core/encoding';
import { LocalVault } from '../../src/core/vault';

describe('actual Olm WASM contract', () => {
  it('exchanges authenticated messages, exposes inbound sender, restores ratchets', () => {
    const a = new Account(), b = new Account();
    a.generateOneTimeKeys(1);
    const identity = JSON.parse(a.identityKeys());
    const keys = JSON.parse(a.oneTimeKeys()).curve25519;
    const outgoing = b.createOutboundSession(identity.curve25519, Object.values(keys)[0] as string);
    const encrypted = JSON.parse(outgoing.encrypt('hello synthetic'));
    const inbound = a.createInboundSession(encrypted.body);
    expect(inbound.plaintext).toBe('hello synthetic');
    expect(inbound.senderIdentityKey).toBe(JSON.parse(b.identityKeys()).curve25519);
    const incoming = inbound.takeSession();
    const reply = JSON.parse(incoming.encrypt('reply synthetic'));
    const restored = Session.fromPickle(outgoing.pickle());
    expect(restored.decrypt(reply.type, reply.body)).toBe('reply synthetic');
    expect(() => restored.decrypt(reply.type, reply.body)).toThrow();
    incoming.free(); outgoing.free(); restored.free(); inbound.free(); a.free(); b.free();
  });
});

describe('fixed opaque packets', () => {
  it('pads to 32768 bytes and rejects oversized or malformed packets', () => {
    const packet = encodePacket({v:1, type:0, body:'synthetic'});
    expect(atob(packet).length).toBe(32768);
    expect(decodePacket(packet)).toEqual({v:1,type:0,body:'synthetic'});
    expect(() => encodePacket({body:'x'.repeat(33000)})).toThrow();
    expect(() => decodePacket('eA==')).toThrow();
    expect(normalizeRelay('http://127.0.0.1:8765/')).toBe('http://127.0.0.1:8765');
    expect(() => normalizeRelay('http://relay.example')).toThrow();
    expect(() => normalizeRelay('https://user:secret@relay.example')).toThrow();
  });
});

describe('nonrecoverable encrypted local vault', () => {
  it('persists only encrypted state with a nonextractable key and survives reopen', async () => {
    const name = 'test-' + randomHex();
    const vault = await LocalVault.open<{secret:string}>(name, () => ({secret:'initial'}));
    await vault.lock(async () => { const state = await vault.load(); state.secret = 'private synthetic history'; await vault.save(state); });
    vault.close();
    const reopened = await LocalVault.open(name, () => ({secret:'new'}));
    expect((await reopened.load()).secret).toBe('private synthetic history');
    const db = await new Promise<IDBDatabase>((resolve,reject) => { const r=indexedDB.open(name); r.onsuccess=()=>resolve(r.result); r.onerror=()=>reject(r.error); });
    const record = await new Promise<any>((resolve,reject) => {const r=db.transaction('vault').objectStore('vault').get('profile');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
    expect(JSON.stringify(record)).not.toContain('private synthetic history');
    expect(record.key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw',record.key)).rejects.toThrow();
    db.close(); reopened.close();
  });
  it('rejects stale writes instead of rolling a ratchet back', async () => {
    const name='test-'+randomHex();
    const a=await LocalVault.open(name,()=>({value:0}));
    const b=await LocalVault.open(name,()=>({value:0}));
    const sa=await a.load(), sb=await b.load(); sa.value=1; sb.value=2;
    await a.save(sa);
    await expect(b.save(sb)).rejects.toThrow(/outra aba/i);
    expect((await b.load()).value).toBe(1);
    a.close();b.close();
  });
});
