// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ChatClient, ChatSnapshot } from '../../src/core/chat';
import { MessengerApp } from '../../src/ui/app';

function fixture(onboarded = true, verified = false) {
  const state: ChatSnapshot = {
    contacts: [{ id: 'contact-a', label: '<img src=x onerror=alert(1)>', fingerprint: 'a'.repeat(64), verified, peerVerified: verified, status: verified ? 'ready' : 'pending', relay: 'http://localhost:8080', rotationPending: false }],
    invitations: [], messages: [], settings: { relay: 'http://localhost:8080', onboarded },
  };
  const listeners = new Set<() => void>();
  const client = {
    snapshot: () => structuredClone(state),
    subscribe: (listener: () => void) => { listeners.add(listener); return () => listeners.delete(listener); },
    sync: vi.fn(async () => {}), close: vi.fn(async () => {}),
    setSettings: vi.fn(async (settings: Partial<ChatSnapshot['settings']>) => { Object.assign(state.settings, settings); listeners.forEach(fn => fn()); }),
    sendText: vi.fn(async () => 'message-id'), sendFile: vi.fn(async () => 'file-id'),
    createInvite: vi.fn(), acceptInvite: vi.fn(), verifyContact: vi.fn(),
    downloadFile: vi.fn(), rotateQueue: vi.fn(), removeContact: vi.fn(), wipe: vi.fn(async () => {}),
  };
  const root = document.createElement('div');
  document.body.append(root);
  const app = new MessengerApp(root, client as unknown as ChatClient);
  app.mount();
  return { app, root, client, state, refresh: () => listeners.forEach(fn => fn()) };
}

const cleanups: (() => void)[] = [];
afterEach(() => { cleanups.splice(0).forEach(fn => fn()); document.body.replaceChildren(); });

function button(root: HTMLElement, text: string): HTMLButtonElement {
  const found = [...root.querySelectorAll('button')].find(el => el.textContent?.trim() === text || el.getAttribute('aria-label') === text);
  if (!found) throw new Error(`Button not found: ${text}`);
  return found;
}

describe('messenger UI safety boundaries', () => {
  it('requires a no recovery acknowledgment before onboarding', async () => {
    const f = fixture(false); cleanups.push(() => f.app.destroy());
    const start = button(f.root, 'Criar meu espaço local');
    expect(start.disabled).toBe(true);
    expect(f.root.textContent).toContain('não há recuperação');
    const checkbox = f.root.querySelector<HTMLInputElement>('input[type=checkbox]')!;
    checkbox.checked = true; checkbox.dispatchEvent(new Event('change', { bubbles: true }));
    expect(start.disabled).toBe(false);
    start.click(); await vi.waitFor(() => expect(f.root.querySelector('.messenger')).not.toBeNull());
    expect(f.state.settings.onboarded).toBe(true);
  });

  it('renders contact names as text and blocks unverified sends', () => {
    const f = fixture(); cleanups.push(() => f.app.destroy());
    button(f.root, '<img src=x onerror=alert(1)>').click();
    expect(f.root.querySelector('img[src="x"]')).toBeNull();
    expect(button(f.root, 'Enviar mensagem').disabled).toBe(true);
    expect(f.root.textContent).toContain('Conferir vínculo');
  });

  it('requires the full fingerprint instead of a checkbox for verification', () => {
    const f = fixture(); cleanups.push(() => f.app.destroy());
    button(f.root, '<img src=x onerror=alert(1)>').click();
    button(f.root, 'Conferir vínculo').click();
    const confirm = button(f.root, 'Confirmar vínculo');
    expect(confirm.disabled).toBe(true);
    const input = f.root.querySelector<HTMLInputElement>('input[name=fingerprint]')!;
    input.value = 'a'.repeat(63); input.dispatchEvent(new Event('input', { bubbles: true }));
    expect(confirm.disabled).toBe(true);
    input.value = 'aaaa '.repeat(16); input.dispatchEvent(new Event('input', { bubbles: true }));
    expect(confirm.disabled).toBe(false);
  });

  it('renders incoming text without executing markup', () => {
    const f = fixture(true, true); cleanups.push(() => f.app.destroy());
    f.state.messages.push({ id: 'message-1', contactId: 'contact-a', direction: 'incoming', kind: 'text', text: '<script>alert(1)</script>', createdAt: Date.now(), status: 'delivered' });
    f.refresh(); button(f.root, '<img src=x onerror=alert(1)>').click();
    expect(f.root.querySelector('script')).toBeNull();
    expect(f.root.textContent).toContain('<script>alert(1)</script>');
  });

  it('requires an exact typed confirmation before deleting local state', () => {
    const f = fixture(); cleanups.push(() => f.app.destroy());
    button(f.root, 'Configurações').click();
    button(f.root, 'Apagar este espaço').click();
    const wipe = button(f.root, 'Apagar definitivamente');
    expect(wipe.disabled).toBe(true);
    const input = f.root.querySelector<HTMLInputElement>('input[name=wipe]')!;
    input.value = 'APAGAR'; input.dispatchEvent(new Event('input', { bubbles: true }));
    expect(wipe.disabled).toBe(false);
    expect(f.client.wipe).not.toHaveBeenCalled();
  });
});
