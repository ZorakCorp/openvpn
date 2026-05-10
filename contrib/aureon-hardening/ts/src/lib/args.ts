export function takeFlag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1 || i + 1 >= argv.length) return undefined;
  return argv[i + 1];
}

export function takeManyAfterFlag(argv: string[], name: string): string[] {
  const i = argv.indexOf(name);
  if (i === -1) return [];
  const out: string[] = [];
  for (let k = i + 1; k < argv.length && !argv[k]!.startsWith("--"); k++) {
    out.push(argv[k]!);
  }
  return out;
}

export function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

export function takeInt(argv: string[], name: string, fallback: number): number {
  const v = takeFlag(argv, name);
  if (v === undefined) return fallback;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

export function takeFloat(argv: string[], name: string, fallback: number): number {
  const v = takeFlag(argv, name);
  if (v === undefined) return fallback;
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : fallback;
}

