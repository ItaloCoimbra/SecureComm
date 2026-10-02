export function formatFingerprint(value: string): string {
  return value.match(/.{1,4}/g)?.join(' ') ?? '';
}

export function previewKind(mime: string): 'image' | 'audio' | null {
  const base = mime.split(';')[0]?.trim().toLowerCase();
  if (['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/avif'].includes(base ?? '')) return 'image';
  if (['audio/webm', 'audio/ogg', 'audio/mpeg', 'audio/mp4', 'audio/wav'].includes(base ?? '')) return 'audio';
  return null;
}

export function safeFilename(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f/\\:*?"<>|\u202a-\u202e\u2066-\u2069]/g, '_').slice(0, 180) || 'arquivo';
}

export function formatBytes(value: number): string {
  const size = Math.max(0, Number.isFinite(value) ? value : 0);
  const index = size < 1024 ? 0 : size < 1024 ** 2 ? 1 : 2;
  return `${new Intl.NumberFormat('pt-BR', { maximumFractionDigits: 1 }).format(size / 1024 ** index)} ${['B', 'KB', 'MB'][index]}`;
}

export function formatTime(timestamp: number): string {
  return new Intl.DateTimeFormat('pt-BR', { hour: '2-digit', minute: '2-digit' }).format(timestamp);
}
