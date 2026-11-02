#!/usr/bin/env node
'use strict';

const usage = 'Usage: vauth-login [--renew] [--version] [--help]\n       vauth-login env [--ir://json] [--renew] [--version] [--help]\n';

async function main() {
  const args = process.argv.slice(2);
  const envOutput = args[0] === 'env';
  if(envOutput) args.shift();
  const allowed = ['--renew', '--version', '--help'];
  if(envOutput) allowed.push('--ir://json');
  if(args.some(arg => !allowed.includes(arg)))
    throw new Error(usage.trim());
  if(args.includes('--help')) {
    process.stdout.write(usage);
    return;
  }
  if(args.includes('--version')) {
    process.stdout.write(require('../package.json').version + '\n');
    return;
  }
  const VauthLogin = require('../index');
  const client = new VauthLogin();
  const token = await client.Connect(args.includes('--renew'));
  if(!token)
    throw new Error('Could not login to vault: no authentication method available');
  if(envOutput) {
    process.stdout.write(JSON.stringify({VAULT_TOKEN : token, VAULT_ADDR : client.VAULT_ADDR || ''}) + '\n');
    return;
  }
  process.stdout.write(token, () => process.stderr.write('\n'));
}

main().catch(err => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
