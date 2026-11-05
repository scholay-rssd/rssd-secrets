#!/usr/bin/env node
// Fails when RSSD code reads a secret-like environment variable that
// schema.json does not declare. Usage: node scripts/coverage.mjs <rssd checkout>
import {readdir, readFile} from 'node:fs/promises';
import {extname, join, relative} from 'node:path';
import {schema} from '../src/index.mjs';

const SKIP_DIRS = new Set(['.git', 'node_modules', 'target', 'dist', 'tests', 'center', '.local']);
const EXTENSIONS = new Set(['.mjs', '.js', '.cjs', '.ts', '.tsx', '.rs', '.py', '.sh', '.yml', '.yaml']);
const READS = [
  /\b(?:process\.)?env(?:\.|\[\s*['"])([A-Z][A-Z0-9_]+)/g,
  /env::var(?:_os)?\(\s*"([A-Z][A-Z0-9_]+)"/g,
  /\benviron(?:\.get)?[[(]\s*['"]([A-Z][A-Z0-9_]+)/g,
  /\bsecrets\.([A-Z][A-Z0-9_]+)/g,
];
const SECRET_LIKE = /(TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|_KEY)(_FILE)?$/;
const IGNORED = new Set(['GITHUB_TOKEN']);

export async function secretReads(root) {
  const found = new Map();
  async function walk(directory) {
    for (const item of await readdir(directory, {withFileTypes: true})) {
      const path = join(directory, item.name);
      if (item.isDirectory()) { if (!SKIP_DIRS.has(item.name)) await walk(path); continue; }
      if (!item.isFile() || !EXTENSIONS.has(extname(item.name)) || /\.test\.|\.spec\./.test(item.name)) continue;
      const text = await readFile(path, 'utf8');
      for (const pattern of READS) for (const match of text.matchAll(pattern)) {
        const name = match[1];
        if (!SECRET_LIKE.test(name) || IGNORED.has(name)) continue;
        if (!found.has(name)) found.set(name, relative(root, path));
      }
    }
  }
  await walk(root);
  return found;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = process.argv[2];
  if (!root) { console.error('Usage: node scripts/coverage.mjs <rssd checkout>'); process.exit(2); }
  const declared = new Set(schema.secrets.map((entry) => entry.name));
  const reads = await secretReads(root);
  const undeclared = [...reads].filter(([name]) => !declared.has(name));
  for (const [name, file] of undeclared) console.error(`Undeclared secret ${name} (first read in ${file})`);
  console.log(`${reads.size} secret-like variables read, ${undeclared.length} undeclared`);
  process.exitCode = undeclared.length ? 1 : 0;
}
