#!/usr/bin/env node
'use strict';

const usage = 'Usage: vauth-login [--renew] [--version] [--help]\n';

async function main() {
  const args = process.argv.slice(2);
  if(args.some(arg => !['--renew', '--version', '--help'].includes(arg)))
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
  const token = await new VauthLogin().connect(args.includes('--renew'));
  if(!token)
    throw new Error('Could not login to vault: no authentication method available');
  process.stdout.write(token);
}

main().catch(err => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
