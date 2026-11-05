#!/usr/bin/env node
import {resolveComponent, runWithSecrets, schema, secretsFor} from '../src/index.mjs';

const USAGE = `Usage:
  rssd-secrets list [--component NAME]
  rssd-secrets check [--component NAME] [options]
  rssd-secrets exec [--component NAME] [options] [--allow-missing] -- COMMAND [ARGS...]

Options:
  --dir PATH          values directory (default: RSSD_SECRETS_DIR)
  --server-dir PATH   private server directory (default on Linux: ${schema.serverDirectory})
  --no-credential-store  skip macOS Keychain / Windows Credential Manager

Values are never printed. Components: ${Object.keys(schema.components).join(', ')}`;

function parse(argv) {
  const [command, ...rest] = argv, options = {}, separator = rest.indexOf('--');
  const flags = separator < 0 ? rest : rest.slice(0, separator);
  const child = separator < 0 ? [] : rest.slice(separator + 1);
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i], next = () => { if (i + 1 >= flags.length) throw Error(flag + ' needs a value'); return flags[++i]; };
    if (flag === '--component') options.component = next();
    else if (flag === '--dir') options.dir = next();
    else if (flag === '--server-dir') options.serverDir = next();
    else if (flag === '--no-credential-store') options.credentialStore = false;
    else if (flag === '--allow-missing') options.allowMissing = true;
    else throw Error('Unknown option: ' + flag);
  }
  return {command, options, child};
}

async function main() {
  const {command, options, child} = parse(process.argv.slice(2));
  if (command === 'list') {
    for (const entry of secretsFor(options.component)) console.log(`${entry.name}\t${entry.type}\t${entry.components.join(',')}\t${entry.purpose}`);
    return 0;
  }
  if (command === 'check') {
    const {results, missing} = await resolveComponent(options.component, options);
    const required = new Set(secretsFor(options.component).filter((e) => e.required).map((e) => e.name));
    for (const result of results) console.log(`${result.name}\t${result.source ?? 'missing'}${required.has(result.name) ? '\trequired' : ''}`);
    if (missing.length) { console.error('Missing required secrets: ' + missing.join(', ')); return 1; }
    return 0;
  }
  if (command === 'exec') {
    if (!child.length) throw Error('exec needs a command after --');
    return runWithSecrets(child[0], child.slice(1), options);
  }
  console.error(USAGE);
  return command ? 2 : 0;
}

main().then((code) => { process.exitCode = code; }, (error) => { console.error(error.message); process.exitCode = 1; });
