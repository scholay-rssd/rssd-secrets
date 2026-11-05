// Resolves the secrets declared in schema.json. RSSD code only reads
// environment variables; this module decides where each value comes from and
// never logs one.
import {spawn, spawnSync} from 'node:child_process';
import {chmod, mkdtemp, readFile, rm, stat, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const TYPES = new Set(['value', 'file', 'location', 'runtime']);

export const schema = JSON.parse(await readFile(new URL('../schema.json', import.meta.url), 'utf8'));

export function validateSchema(value) {
  if (!value || value.version !== 1 || typeof value.components !== 'object') throw Error('Unsupported schema');
  const seen = new Set();
  for (const entry of value.secrets) {
    if (!NAME.test(entry.name) || seen.has(entry.name)) throw Error('Invalid or duplicate secret name: ' + entry.name);
    if (!TYPES.has(entry.type)) throw Error(`${entry.name}: unknown type ${entry.type}`);
    if (!entry.components?.length || entry.components.some((c) => !(c in value.components))) throw Error(`${entry.name}: unknown component`);
    if (typeof entry.required !== 'boolean' || !entry.purpose) throw Error(`${entry.name}: required and purpose are mandatory`);
    seen.add(entry.name);
  }
  return value;
}

export function secretsFor(component, source = schema) {
  if (!component) return source.secrets;
  if (!(component in source.components)) throw Error('Unknown component: ' + component);
  return source.secrets.filter((entry) => entry.components.includes(component));
}

function entryFor(nameOrEntry, source) {
  if (typeof nameOrEntry === 'object') return nameOrEntry;
  const entry = source.secrets.find((item) => item.name === nameOrEntry);
  if (!entry) throw Error('Undeclared secret: ' + nameOrEntry);
  return entry;
}

function defaultRun(command, args, options) {
  return spawnSync(command, args, {encoding: 'utf8', timeout: 10_000, ...options});
}

// Multi-line values (keys) are stored in OS credential stores as "base64:…",
// because `security -w` prints hex for values containing newlines.
function decodeStored(text) {
  return text.startsWith('base64:') ? Buffer.from(text.slice(7), 'base64').toString('utf8') : text;
}

function readCredentialStore(name, {platform, service, run}) {
  if (platform === 'darwin') {
    const result = run('/usr/bin/security', ['find-generic-password', '-s', service, '-a', name, '-w']);
    return result.status === 0 && result.stdout ? decodeStored(result.stdout.replace(/\n$/, '')) : null;
  }
  if (platform === 'win32') {
    const script = "$ErrorActionPreference='Stop';[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];"
      + 'try{$c=(New-Object Windows.Security.Credentials.PasswordVault).Retrieve($env:RSSD_SECRETS_SERVICE,$env:RSSD_SECRETS_NAME);$c.RetrievePassword();[Console]::Out.Write($c.Password)}catch{exit 3}';
    const result = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {env: {...process.env, RSSD_SECRETS_SERVICE: service, RSSD_SECRETS_NAME: name}});
    return result.status === 0 && result.stdout ? decodeStored(result.stdout) : null;
  }
  return null;
}

async function directoryEntry(directory, name, requirePrivate) {
  const path = join(directory, name);
  let info;
  try { info = await stat(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  if (!info.isFile()) throw Error(`${path} is not a file`);
  if (requirePrivate && (info.mode & 0o077)) throw Error(`${path} must not be accessible by group or others`);
  return path;
}

async function directoryValue(path) {
  const text = (await readFile(path, 'utf8')).replace(/\r?\n$/, '');
  return text || null;
}

function settings(options, source) {
  const env = options.env ?? process.env, platform = options.platform ?? process.platform;
  const dir = options.dir ?? env.RSSD_SECRETS_DIR;
  const serverDir = options.serverDir !== undefined ? options.serverDir : env.RSSD_SECRETS_SERVER_DIR ?? (platform === 'linux' ? source.serverDirectory : null);
  return {
    env, platform, run: options.run ?? defaultRun,
    dir: dir ? resolve(dir) : null,
    serverDir: serverDir || null,
    credentialStore: options.credentialStore !== false,
    service: options.service ?? source.keychainService,
  };
}

// Returns {name, source} plus `value` (string) or, for file secrets found in a
// credential store, `content` that must be materialized before use.
export async function resolveSecret(nameOrEntry, options = {}) {
  const source = options.schema ?? schema, entry = entryFor(nameOrEntry, source), s = settings(options, source);
  const {name, type} = entry;
  if (type === 'runtime') return {name, source: 'runtime'};
  if (s.env[name]) return {name, source: 'env', value: s.env[name]};
  if (type === 'location') return {name, source: null};
  if (s.dir) {
    const path = await directoryEntry(s.dir, name, false);
    if (path) {
      const value = type === 'file' ? path : await directoryValue(path);
      if (value) return {name, source: 'dir', value};
    }
  }
  if (s.credentialStore) {
    const stored = readCredentialStore(name, s);
    if (stored) return type === 'file' ? {name, source: 'credential-store', content: stored} : {name, source: 'credential-store', value: stored};
  }
  if (s.serverDir) {
    const path = await directoryEntry(s.serverDir, name, true);
    if (path) {
      const value = type === 'file' ? path : await directoryValue(path);
      if (value) return {name, source: 'server-dir', value};
    }
  }
  return {name, source: null};
}

export function missingRequirements(entries, results) {
  const found = new Set(results.filter((r) => r.value !== undefined || r.content !== undefined).map((r) => r.name));
  const missing = [];
  const groups = new Map();
  for (const entry of entries) if (entry.group) groups.set(entry.group, [...(groups.get(entry.group) ?? []), entry]);
  for (const entry of entries) {
    if (!entry.required || entry.type === 'runtime') continue;
    const members = entry.group ? groups.get(entry.group) : [entry];
    if (!members.some((member) => found.has(member.name))) missing.push(members.map((member) => member.name).join(' or '));
  }
  return [...new Set(missing)];
}

// Resolves every secret of a component. With `materialize`, credential-store
// contents of file secrets are written to a private temporary directory that
// `cleanup()` removes.
export async function resolveComponent(component, options = {}) {
  const source = options.schema ?? schema, entries = secretsFor(component, source);
  const results = [];
  for (const entry of entries) results.push(await resolveSecret(entry, {...options, schema: source}));
  let directory = null;
  if (options.materialize) {
    for (const result of results) {
      if (result.content === undefined) continue;
      directory ??= await mkdtemp(join(tmpdir(), 'rssd-secrets-'));
      await chmod(directory, 0o700);
      const path = join(directory, result.name);
      await writeFile(path, result.content, {mode: 0o600});
      result.value = path;
      delete result.content;
    }
  }
  return {
    results,
    missing: missingRequirements(entries, results),
    cleanup: async () => { if (directory) await rm(directory, {recursive: true, force: true}); },
  };
}

export function injectedEnvironment(results, env = process.env) {
  const next = {...env};
  for (const result of results) if (result.source !== 'env' && typeof result.value === 'string') next[result.name] = result.value;
  return next;
}

export async function runWithSecrets(command, args, {component, allowMissing = false, ...options} = {}) {
  const {results, missing, cleanup} = await resolveComponent(component, {...options, materialize: true});
  try {
    if (missing.length && !allowMissing) throw Error('Missing required secrets: ' + missing.join(', '));
    const child = spawn(command, args, {stdio: 'inherit', env: injectedEnvironment(results, options.env ?? process.env), shell: process.platform === 'win32'});
    const forward = (signal) => child.kill(signal);
    process.on('SIGINT', forward).on('SIGTERM', forward);
    try {
      return await new Promise((done, fail) => {
        child.once('error', fail);
        child.once('close', (code, signal) => done(code ?? (signal ? 128 + 15 : 1)));
      });
    } finally {
      process.off('SIGINT', forward).off('SIGTERM', forward);
    }
  } finally {
    await cleanup();
  }
}
