type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  for (const child of children) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
}

export function action(label: string, onClick: () => void, className = 'button'): HTMLButtonElement {
  const node = el('button', className, label);
  node.type = 'button';
  node.addEventListener('click', onClick);
  return node;
}

const paths: Record<string, string[]> = {
  shield: ['M12 3 4.5 6v5c0 4.6 3.1 8.1 7.5 10 4.4-1.9 7.5-5.4 7.5-10V6L12 3Z', 'm8.5 12 2.3 2.3 4.7-5'],
  plus: ['M12 5v14M5 12h14'],
  link: ['m9 15 6-6', 'M7.6 16.4 6 18a3.5 3.5 0 0 1-5-5l4-4a3.5 3.5 0 0 1 5 0', 'm16.4 7.6 1.6-1.6a3.5 3.5 0 0 1 5 5l-4 4a3.5 3.5 0 0 1-5 0'],
  settings: ['M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z', 'm10 3-.5 2-2 .8-1.8-1-2 3.4 1.5 1.4-.2 2.2-1.7 1.2 1.7 3.6 2-.3 1.6 1.6-.1 2 3.8 1.1 1-1.8 2.3-.4 1.5 1.3 3-2.5-.8-1.9.8-2.1 2-.6-.2-4-2-.4-1.2-1.9.6-2-3.4-2-1.4 1.5-2.2-.2L14 3h-4Z'],
  send: ['m3 3 18 9-18 9 4-9-4-9Zm4 9h14'],
  paperclip: ['m8 12 6-6a3 3 0 0 1 4.2 4.2l-8 8a5 5 0 0 1-7.1-7.1l8.6-8.6', 'm6.8 13.2 7-7'],
  microphone: ['M9 5a3 3 0 0 1 6 0v7a3 3 0 0 1-6 0V5Z', 'M5 10v2a7 7 0 0 0 14 0v-2M12 19v3M8 22h8'],
  back: ['m14 5-7 7 7 7'],
  close: ['m6 6 12 12M6 18 18 6'],
  refresh: ['M20 7v5h-5', 'M4 17v-5h5', 'M5.5 7a7.5 7.5 0 0 1 12-1L20 9M4 15l2.5 3a7.5 7.5 0 0 0 12-1'],
  document: ['M6 3h8l4 4v14H6V3Z', 'M14 3v5h4M9 12h6M9 16h6'],
  lock: ['M7 10V7a5 5 0 0 1 10 0v3', 'M5 10h14v11H5V10Z', 'M12 14v3'],
  check: ['m5 12 4 4L19 6'],
  more: ['M5 12h.01M12 12h.01M19 12h.01'],
};

export function icon(name: string): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.7', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(key, value);
  for (const value of paths[name] ?? paths.shield!) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', value); svg.append(path);
  }
  return svg;
}

export function iconButton(label: string, name: string, onClick: () => void, className = 'icon-button'): HTMLButtonElement {
  const node = action('', onClick, className); node.setAttribute('aria-label', label); node.title = label; node.append(icon(name)); return node;
}

export function field(label: string, name: string, value = '', multiline = false): { wrapper: HTMLLabelElement; input: HTMLInputElement | HTMLTextAreaElement } {
  const input = multiline ? el('textarea', 'input') : el('input', 'input');
  input.name = name; input.value = value; input.autocomplete = 'off'; input.spellcheck = false;
  input.setAttribute('autocapitalize', 'off');
  return { wrapper: el('label', 'field', el('span', 'field-label', label), input), input };
}
