import { describe, expect, it } from 'vitest';
import { formatBytes, formatFingerprint, previewKind, safeFilename } from '../../src/ui/presentation';

describe('private messenger presentation', () => {
  it('renders a full fingerprint without truncating verification material', () => {
    const fingerprint = '0123456789abcdef'.repeat(4);
    expect(formatFingerprint(fingerprint).replaceAll(' ', '')).toBe(fingerprint);
    expect(formatFingerprint(fingerprint)).toContain('0123 4567 89ab cdef');
  });

  it('limits automatic previews to passive raster images and supported audio', () => {
    expect(previewKind('image/png')).toBe('image');
    expect(previewKind('audio/webm;codecs=opus')).toBe('audio');
    expect(previewKind('image/svg+xml')).toBe(null);
    expect(previewKind('text/html')).toBe(null);
    expect(previewKind('application/pdf')).toBe(null);
  });

  it('removes path and control characters from downloaded filenames', () => {
    expect(safeFilename('../folder\\report\u0000.pdf')).toBe('.._folder_report_.pdf');
    expect(safeFilename('')).toBe('arquivo');
  });

  it('shows human readable bounded sizes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1024)).toBe('1 KB');
    expect(formatBytes(1536)).toBe('1,5 KB');
    expect(formatBytes(1048576)).toBe('1 MB');
  });
});
