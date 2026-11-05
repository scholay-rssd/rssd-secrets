import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmod, mkdtemp, mkdir, readFile, readdir, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {missingRequirements, resolveComponent, resolveSecret, schema, validateSchema} from '../src/index.mjs';
import {secretReads} from '../scripts/coverage.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'bin/rssd-secrets.mjs');
const isolated = {env: {}, platform: 'test', credentialStore: false, serverDir: null};
const noStore = () => ({status: 44, stdout: ''});

test('schema is valid and every demo value is declared', async () => {
  validateSchema(schema);
  const declared = new Set(schema.secrets.map((entry) => entry.name));
  for (const name of await readdir(join(root, 'examples/demo'))) if (name !== 'README.md') assert.ok(declared.has(name), name);
});

test('environment wins over every other source', async () => {
  const result = await resolveSecret('SCHOLAY_WORKER_TOKEN', {...isolated, env: {SCHOLAY_WORKER_TOKEN: 'from-env'}, dir: join(root, 'examples/demo')});
  assert.deepEqual(result, {name: 'SCHOLAY_WORKER_TOKEN', source: 'env', value: 'from-env'});
});

test('values directory supplies values and file paths', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rssd-secrets-test-'));
  await writeFile(join(dir, 'SCHOLAY_INGEST_TOKEN'), 'ingest\n');
  await writeFile(join(dir, 'SCHOLAY_UPDATER_KEY_FILE'), 'key material');
  assert.equal((await resolveSecret('SCHOLAY_INGEST_TOKEN', {...isolated, dir})).value, 'ingest');
  assert.equal((await resolveSecret('SCHOLAY_UPDATER_KEY_FILE', {...isolated, dir})).value, join(dir, 'SCHOLAY_UPDATER_KEY_FILE'));
});

test('credential store contents are decoded and file secrets are materialized privately', async () => {
  const stored = {SCHOLAY_TIKHUB_KEY: 'tikhub', SCHOLAY_UPDATER_KEY_FILE: 'base64:' + Buffer.from('line one\nline two').toString('base64')};
  const calls = [];
  const run = (command, args) => { calls.push([command, args]); const name = args[args.indexOf('-a') + 1]; return stored[name] ? {status: 0, stdout: stored[name] + '\n'} : {status: 44, stdout: ''}; };
  const options = {env: {}, platform: 'darwin', run, serverDir: null};
  assert.equal((await resolveSecret('SCHOLAY_TIKHUB_KEY', options)).value, 'tikhub');
  assert.equal(calls[0][0], '/usr/bin/security');
  assert.ok(calls[0][1].includes('rssd-secrets'));
  const {results, cleanup} = await resolveComponent('desktop-release', {...options, materialize: true});
  const file = results.find((r) => r.name === 'SCHOLAY_UPDATER_KEY_FILE');
  assert.equal(file.source, 'credential-store');
  assert.equal(await readFile(file.value, 'utf8'), 'line one\nline two');
  await cleanup();
  await assert.rejects(readFile(file.value));
});

test('server directory requires private files', async () => {
  const serverDir = await mkdtemp(join(tmpdir(), 'rssd-secrets-server-'));
  await writeFile(join(serverDir, 'SCHOLAY_WORKER_TOKEN'), 'worker', {mode: 0o644});
  await chmod(join(serverDir, 'SCHOLAY_WORKER_TOKEN'), 0o644);
  await assert.rejects(resolveSecret('SCHOLAY_WORKER_TOKEN', {...isolated, serverDir}), /group or others/);
  await chmod(join(serverDir, 'SCHOLAY_WORKER_TOKEN'), 0o600);
  assert.deepEqual(await resolveSecret('SCHOLAY_WORKER_TOKEN', {...isolated, serverDir}), {name: 'SCHOLAY_WORKER_TOKEN', source: 'server-dir', value: 'worker'});
});

test('runtime and location entries are never read from stores', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rssd-secrets-test-'));
  await writeFile(join(dir, 'RSSD_ASSISTANT_KEY'), 'stored');
  await writeFile(join(dir, 'SCHOLAY_AUTH_DIR'), 'stored');
  assert.equal((await resolveSecret('RSSD_ASSISTANT_KEY', {...isolated, dir})).source, 'runtime');
  assert.equal((await resolveSecret('SCHOLAY_AUTH_DIR', {...isolated, dir})).source, null);
});

test('required secrets and groups are reported by name', () => {
  const entries = [
    {name: 'A', required: true, type: 'value'},
    {name: 'B', required: true, type: 'value', group: 'g'},
    {name: 'C', required: false, type: 'file', group: 'g'},
  ];
  assert.deepEqual(missingRequirements(entries, [{name: 'C', source: 'dir', value: '/x'}]), ['A']);
  assert.deepEqual(missingRequirements(entries, []), ['A', 'B or C']);
});

test('undeclared names are rejected', async () => {
  await assert.rejects(resolveSecret('NOT_DECLARED', isolated), /Undeclared/);
});

test('exec injects values, check never prints them', () => {
  const env = {...process.env, RSSD_SECRETS_DIR: join(root, 'examples/demo')};
  delete env.SCHOLAY_WORKER_TOKEN;
  const exec = spawnSync(process.execPath, [cli, 'exec', '--component', 'admin-worker', '--no-credential-store', '--server-dir', '', '--', process.execPath, '-e', 'process.stdout.write(process.env.SCHOLAY_WORKER_TOKEN)'], {env, encoding: 'utf8'});
  assert.equal(exec.status, 0, exec.stderr);
  assert.equal(exec.stdout, 'demo-worker-token-not-a-secret');
  const check = spawnSync(process.execPath, [cli, 'check', '--no-credential-store', '--server-dir', ''], {env, encoding: 'utf8'});
  assert.equal(check.status, 1);
  assert.match(check.stdout, /SCHOLAY_WORKER_TOKEN\tdir\trequired/);
  assert.doesNotMatch(check.stdout + check.stderr, /not-a-secret/);
  assert.match(check.stderr, /RSSD_RECEIVER_CONFIG/);
});

test('exec refuses to start when a required secret is missing', () => {
  const env = {...process.env};
  delete env.SCHOLAY_WORKER_TOKEN; delete env.RSSD_SECRETS_DIR;
  const exec = spawnSync(process.execPath, [cli, 'exec', '--component', 'admin-worker', '--no-credential-store', '--server-dir', '', '--', process.execPath, '-e', 'process.exit(0)'], {env, encoding: 'utf8'});
  assert.equal(exec.status, 1);
  assert.match(exec.stderr, /Missing required secrets: SCHOLAY_WORKER_TOKEN/);
});

test('coverage finds secret-like reads outside tests and the center', async () => {
  const checkout = await mkdtemp(join(tmpdir(), 'rssd-secrets-coverage-'));
  await mkdir(join(checkout, 'admin')); await mkdir(join(checkout, 'center')); await mkdir(join(checkout, 'tests'));
  await writeFile(join(checkout, 'admin/a.mjs'), "const t=process.env.SCHOLAY_WORKER_TOKEN, n=process.env['NEW_API_KEY'], p=process.env.PORT;");
  await writeFile(join(checkout, 'admin/b.rs'), 'std::env::var("OTHER_SECRET")');
  await writeFile(join(checkout, 'center/c.ts'), 'process.env.JWT_SECRET');
  await writeFile(join(checkout, 'tests/d.mjs'), 'process.env.TEST_TOKEN');
  assert.deepEqual([...(await secretReads(checkout)).keys()].sort(), ['NEW_API_KEY', 'OTHER_SECRET', 'SCHOLAY_WORKER_TOKEN']);
});
