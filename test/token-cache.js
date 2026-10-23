'use strict';

const assert = require('node:assert/strict');
const {test, before, after} = require('node:test');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const {execFile, spawnSync} = require('child_process');
const {promisify, format} = require('util');
const exec = promisify(execFile);
const Vauth = require('../index');

const {encrypt, decrypt} = require('ssh-agent-crypt');
const readCache = async file => JSON.parse(await decrypt(fs.readFileSync(file, 'utf8')));
const writeCache = async (file, cache) => fs.writeFileSync(file, await encrypt(JSON.stringify(cache)));
let agentDirectory, agentPid;
const previousSocket = process.env.SSH_AUTH_SOCK;
const previousIdentity = process.env.VAUTH_USER_IDENTITY;
const previousMail = process.env.VAUTH_USER_MAIL;
const previousCryptKey = process.env.SSH_AGENT_CRYPT_KEY;

before(() => {
  delete process.env.VAUTH_USER_IDENTITY;
  delete process.env.VAUTH_USER_MAIL;
  delete process.env.SSH_AGENT_CRYPT_KEY;
  agentDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-agent-'));
  const key = path.join(agentDirectory, 'key');
  assert.equal(spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]).status, 0);
  const agent = spawnSync('ssh-agent', ['-s'], {encoding : 'utf8'});
  assert.equal(agent.status, 0);
  process.env.SSH_AUTH_SOCK = agent.stdout.match(/SSH_AUTH_SOCK=([^;]+)/)[1];
  agentPid = agent.stdout.match(/SSH_AGENT_PID=(\d+)/)[1];
  assert.equal(spawnSync('ssh-add', [key]).status, 0);
});

after(() => {
  for(const [name, value] of [['VAUTH_USER_IDENTITY', previousIdentity], ['VAUTH_USER_MAIL', previousMail], ['SSH_AGENT_CRYPT_KEY', previousCryptKey]]) {
    if(value === undefined)
      delete process.env[name];
    else
      process.env[name] = value;
  }
  if(agentPid)
    process.kill(Number(agentPid));
  if(previousSocket === undefined)
    delete process.env.SSH_AUTH_SOCK;
  else
    process.env.SSH_AUTH_SOCK = previousSocket;
  fs.rmSync(agentDirectory, {recursive : true, force : true});
});

const HOUR = 60 * 60;

async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-test-'));
  let file;
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await(const chunk of req)
      body += chunk;
    requests.push({path : req.url, method : req.method, token : req.headers['x-vault-token'], body});
    res.setHeader('content-type', 'application/json');
    if(req.url === '/v1/auth/jwt/login') {
      res.end(JSON.stringify({auth : {client_token : 'fresh-token', lease_duration : 24 * HOUR, renewable : true}}));
    } else if(req.url === '/v1/auth/token/lookup-self') {
      res.statusCode = options.lookup_status || 200;
      res.end(JSON.stringify({data : {ttl : options.ttl === undefined ? 12 * HOUR : options.ttl, renewable : options.renewable !== false, creation_ttl : options.creation_ttl === undefined ? 24 * HOUR : options.creation_ttl, entity_id : 'test-entity'}}));
    } else if(req.url === '/v1/auth/token/renew-self') {
      res.statusCode = options.renew_status || 200;
      res.end(JSON.stringify({auth : {client_token : req.headers['x-vault-token'], lease_duration : 24 * HOUR, renewable : true}}));
    } else if(req.url === '/v1/identity/entity/id/test-entity') {
      res.end(JSON.stringify({data : {metadata : {}}}));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, {recursive : true, force : true});
  });
  const client = () => {
    // Avoid reading the real user's environment/configuration/cache.
    const instance = Object.create(Vauth.prototype);
    instance.rc = {jwt_auth : {path : 'jwt', jwt : 'test-jwt', role : 'test-role'}};
    instance.VAULT_ADDR = `http://127.0.0.1:${server.address().port}`;
    instance._token_cache_file = () => path.join(directory, '.vauth', 'tokens', instance._token_cache_key() + '.creds');
    return instance;
  };
  file = client()._token_cache_file();
  const remaining = async (instance, ttl) => {
    const file = instance._token_cache_file();
    const cache = (await readCache(file));
    cache.expires_at = ttl === 0 ? null : Date.now() + ttl * 1000;
    await writeCache(file, cache);
  };
  const seed = async (instance, lease = 12 * HOUR) => {
    await instance._save_cached_token('cached-token', {lease_duration : lease, renewable : options.renewable !== false});
    if(options.ttl !== undefined)
      await remaining(instance, options.ttl);
  };
  const read = async instance => readCache(instance._token_cache_file());
  return {client, seed, read, requests, file, remaining};
}

test('login persists a token; a new instance reuses it without logging in', async t => {
  const {client, read, requests, file} = await fixture(t);
  const first = client();
  assert.equal(await first.connect(), 'fresh-token');
  assert.equal((await read(first)).token, 'fresh-token');
  assert.ok((await read(first)).expires_at > Date.now() + 23 * HOUR * 1000);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const second = client();
  assert.equal(await second.connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), [path.basename(file)]);
});

test('a token in the last third of its lease is renewed and saved', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : HOUR});
  const instance = client();
  await seed(instance, 12 * HOUR);
  assert.equal(await instance.connect(), 'cached-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].token, 'cached-token');
  assert.ok((await read(instance)).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('more than one third remaining does not trigger renewal', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : 4 * HOUR + 1});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.connect(), 'cached-token');
  assert.equal(requests.length, 0);
});

test('expired cached tokens are replaced with a new persisted login', async t => {
  const {client, seed, read, requests, file} = await fixture(t);
  const instance = client();
  await seed(instance);
  const cache = (await readCache(file));
  cache.expires_at = Date.now() - 1000;
  await writeCache(file, cache);
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal((await read(instance)).token, 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('cached tokens are reused without checking revocation', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 403});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.connect(), 'cached-token');
  assert.deepEqual(requests, []);
  await assert.rejects(instance._lookup_token(instance.VAULT_TOKEN));
});

test('nonrenewable tokens nearing expiry trigger reauthentication', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renewable : false});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

for(const status of [400, 403]) {
  test(`rejected renewal (${status}) triggers a new persisted login`, async t => {
    const {client, seed, read, requests} = await fixture(t, {ttl : HOUR, renew_status : status});
    const instance = client();
    await seed(instance);
    assert.equal(await instance.connect(), 'fresh-token');
    assert.equal((await read(instance)).token, 'fresh-token');
    assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self', '/v1/auth/jwt/login']);
  });
}

test('server failures do not generate extra tokens, and connect can be retried', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 500});
  const instance = client();
  await seed(instance);
  instance.VAULT_TOKEN = 'uncached-token';
  await assert.rejects(instance.connect());
  await assert.rejects(instance.connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/lookup-self', '/v1/auth/token/lookup-self']);
});

test('renewal server failures do not generate extra tokens', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  await seed(instance);
  await assert.rejects(instance.connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
});

test('an existing environment token is respected and cached', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  await seed(instance);
  instance.VAULT_TOKEN = 'environment-token';
  assert.equal(await instance.connect(), 'environment-token');
  assert.equal((await read(instance)).token, 'environment-token');
  assert.equal(requests[0].token, 'environment-token');
  assert.equal(requests.length, 1);
});

test('nonexpiring tokens are reused without renewal', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : 0});
  const instance = client();
  await seed(instance, 0);
  assert.equal(await instance.connect(), 'cached-token');
  assert.equal((await read(instance)).expires_at, null);
  assert.equal(requests.length, 0);
});

test('corrupt caches are replaced with a valid cache', async t => {
  const {client, read, file} = await fixture(t);
  fs.mkdirSync(path.dirname(file), {recursive : true});
  fs.writeFileSync(file, '{broken');
  const instance = client();
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal((await read(instance)).token, 'fresh-token');
});

test('cache entries are isolated by Vault address and authentication configuration', async t => {
  const {client, seed, read, file} = await fixture(t);
  const first = client();
  await seed(first);
  const second = client();
  second.rc.jwt_auth.role = 'other-role';
  assert.equal(await second.connect(), 'fresh-token');
  assert.notEqual(first._token_cache_file(), second._token_cache_file());
  assert.equal((await read(first)).token, 'cached-token');
  assert.equal((await read(second)).token, 'fresh-token');
  const third = client();
  third.VAULT_ADDR = 'http://other-vault.test';
  assert.notEqual(third._token_cache_key(), first._token_cache_key());
  assert.equal(fs.readdirSync(path.dirname(file)).length, 2);
  assert.ok(!fs.readFileSync(file, 'utf8').includes('test-jwt'));
});

test('repeated connect calls reuse the established connection', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(requests.length, 1);
});

test('an unwritable cache does not prevent login', async t => {
  const {client, file} = await fixture(t);
  fs.mkdirSync(path.dirname(path.dirname(file)), {recursive : true});
  fs.writeFileSync(path.dirname(file), 'not a directory');
  assert.equal(await client().connect(), 'fresh-token');
});

test('without an auth method inherited tokens and caches are ignored', async t => {
  const {client, seed} = await fixture(t, {lookup_status : 403});
  const instance = client();
  instance.rc = {};
  await seed(instance);
  instance.VAULT_TOKEN = 'uncached-token';
  instance._read_token_cache = async () => { throw new Error('No auth: no cache lookup'); };
  assert.equal(await instance.connect(), undefined);
  assert.equal(instance.VAULT_TOKEN, undefined);
});

test('--renew ignores both environment and cached tokens and saves a new token', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  await seed(instance);
  instance.VAULT_TOKEN = 'environment-token';
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal((await read(instance)).token, 'fresh-token');
  assert.ok((await read(instance)).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('--renew replaces the token of a previously connected instance', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  await seed(instance);
  await instance.connect();
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal((await read(instance)).token, 'fresh-token');
});

test('each successive --renew call forces a new login', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.equal(requests.length, 2);
});

test('--renew without an authentication method remains a no-op', async t => {
  const {client} = await fixture(t);
  const instance = client();
  instance.rc = {};
  assert.equal(await instance.connect(true), undefined);
});


function captureStatus(callback) {
  const lines = [];
  const original = console.error;
  console.error = (...args) => lines.push(format(...args));
  try {
    callback();
  } finally {
    console.error = original;
  }
  return lines;
}

test('token status uses humanDiff with two significant units', () => {
  const instance = Object.create(Vauth.prototype);
  instance.VAULT_ADDR = 'https://vault.example.test';
  const cases = [
    [2 * 86400 + 3 * HOUR + 20 * 60 + 5, '2d 3h'],
    [12 * HOUR + 30 * 60 + 5, '12h 30m'],
    [5 * 60 + 20, '5m 20s'],
    [86400, '1d'],
    [30 * 60, '30m'],
    [45, '45s'],
    [86400 + 20, '1d 20s'],
    [HOUR + 5, '1h 5s'],
    [400 * 86400 + 2 * HOUR, '1y 1month'],
    [60.9, '1m 1s'],
  ];
  for(const [ttl, duration] of cases) {
    assert.deepEqual(captureStatus(() => instance._token_status('reused', {ttl})), [
      `Vauth token: reused · ${duration}`,
    ]);
  }
  assert.deepEqual(captureStatus(() => instance._token_status('renewed', {lease_duration : HOUR + 60})), [
    `Vauth token: renewed · 1h 1m`,
  ]);
  assert.deepEqual(captureStatus(() => instance._token_status('generated', {lease_duration : 0})), [
    `Vauth token: generated · valid indefinitely`,
  ]);
});

for(const options of [
  {ttl : 12 * HOUR, operation : 'reused', duration : '12h'},
  {ttl : HOUR, operation : 'renewed', duration : '1d'},
  {ttl : HOUR, renew_status : 400, operation : 'generated', duration : '1d'},
  {ttl : HOUR, renew_status : 403, operation : 'generated', duration : '1d'},
  {ttl : 0, operation : 'reused', duration : null},
]) {
  test(`one final status per connection: ${JSON.stringify(options)}`, async t => {
    const {client, seed} = await fixture(t, options);
    const instance = client();
    await seed(instance);
    const calls = [];
    instance._token_status = (operation, metadata) => {
      calls.push(...captureStatus(() => Vauth.prototype._token_status.call(instance, operation, metadata)));
    };
    await instance.connect();
    await instance.connect();
    const validity = options.duration ? `valid for ${options.duration}` : 'valid indefinitely';
    assert.deepEqual(calls, [`Vauth token: ${options.operation} · ${validity.replace(/^valid for /, '')}`]);
  });
}

test('failed connections never announce successful token status', async t => {
  const {client, seed} = await fixture(t, {lookup_status : 500});
  const instance = client();
  await seed(instance);
  instance.VAULT_TOKEN = 'uncached-token';
  const calls = [];
  instance._token_status = operation => calls.push(operation);
  await assert.rejects(instance.connect());
  assert.deepEqual(calls, []);
});

for(const [lease, remaining, renew] of [
  [24 * HOUR, 8 * HOUR, true],
  [24 * HOUR, 8 * HOUR + 1, false],
  [HOUR, 20 * 60, true],
  [HOUR, 20 * 60 + 1, false],
  [60, 20, true],
  [60, 21, false],
]) {
  test(`proportional threshold: lease=${lease}, remaining=${remaining}`, async t => {
    const {client, seed, read, requests} = await fixture(t, {ttl : remaining});
    const instance = client();
    await seed(instance, lease);
    await instance.connect();
    assert.equal(requests.some(req => req.path.endsWith('/renew-self')), renew);
    assert.equal((await read(instance)).lease_duration, renew ? 24 * HOUR : lease);
  });
}

test('lookups never reset the original lease duration', async t => {
  const options = {ttl : 20 * HOUR};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  await seed(instance, 24 * HOUR);
  await instance.connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 12 * HOUR);
  await client().connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 8 * HOUR);
  await client().connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 1);
});

test('renewal updates the lease baseline to the newly granted duration', async t => {
  const options = {ttl : 20 * 60};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  await seed(instance, HOUR);
  await instance.connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 8 * HOUR);
  await client().connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 2);
});

test('normal reuse never writes the token cache', async t => {
  const {client, seed, file, requests} = await fixture(t);
  const instance = client();
  await seed(instance);
  instance.VAULT_TOKEN = 'cached-token';
  const before = fs.readFileSync(file, 'utf8');
  const stat = fs.statSync(file);
  instance._save_cached_token = () => { throw new Error('Reuse must not write'); };
  assert.equal(await instance.connect(), 'cached-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.statSync(file).ino, stat.ino);
  assert.equal(fs.statSync(file).mtimeMs, stat.mtimeMs);
  assert.deepEqual(requests, []);
});


test('lookup returns the lease duration and preserves a cached renewal baseline', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, creation_ttl : 24 * HOUR});
  const instance = client();
  const uncached = await instance._lookup_token('environment-token');
  assert.equal(uncached.lease_duration, 24 * HOUR);
  assert.equal(uncached.ttl, HOUR);
  await seed(instance, 12 * HOUR);
  const cached = await instance._lookup_token('cached-token');
  assert.equal(cached.lease_duration, 12 * HOUR);
  assert.equal(requests.length, 2);
});

test('token_cache false skips all cache filesystem access', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client();
  instance.rc.token_cache = false;
  instance._token_cache_file = () => { throw new Error('Disabled cache must not access disk'); };
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(fs.existsSync(file), false);
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('token_cache false ignores existing tokens on disk without deleting them', async t => {
  const {client, seed, requests, file} = await fixture(t);
  const instance = client();
  await seed(instance);
  const before = fs.readFileSync(file, 'utf8');
  instance.rc.token_cache = false;
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  const second = client();
  second.rc.token_cache = false;
  assert.equal(await second.connect(), 'fresh-token');
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('token_cache false still respects an environment token without persisting it', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client();
  instance.rc.token_cache = false;
  instance.VAULT_TOKEN = 'environment-token';
  assert.equal(await instance.connect(), 'environment-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/lookup-self']);
  assert.equal(fs.existsSync(file), false);
});

test('real CLI reads token_cache false from .vauthrc', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.rc, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'index.js');
  for(let i = 0; i < 2; i++) {
    const output = await exec(process.execPath, [cli, 'login', '--source'], {
      cwd : home,
      env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : process.env.SSH_AUTH_SOCK},
    });
    assert.ok(output.stdout.includes("export VAULT_TOKEN='fresh-token'"));
    assert.ok(output.stderr.includes('Vauth token: generated'));
  }
  assert.equal(fs.existsSync(file), false);
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('disk cache contains only armor, interoperable with ssh-agent-crypt CLI', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  await instance.connect();
  const armor = fs.readFileSync(file, 'utf8');
  assert.match(armor, /^ssh-agent-crypt:v3:/);
  assert.ok(!armor.includes('fresh-token'));
  assert.ok(!armor.includes('lease_duration'));
  assert.ok(!armor.includes('test-jwt'));
  const cli = require.resolve('ssh-agent-crypt/bin/ssh-agent-crypt');
  const decoded = spawnSync('bash', [cli, '-decrypt'], {input : armor, encoding : 'utf8'});
  assert.equal(decoded.status, 0);
  assert.equal(JSON.parse(decoded.stdout).token, 'fresh-token');
});

test('a plaintext cache is not accepted as a token cache', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  fs.mkdirSync(path.dirname(file), {recursive : true});
  fs.writeFileSync(file, JSON.stringify({token : 'plaintext-token', lease_duration : 86400, expires_at : Date.now() + 86400000}));
  assert.equal(await instance.connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.match(fs.readFileSync(file, 'utf8'), /^ssh-agent-crypt:v3:/);
});

test('without an SSH agent cache is skipped silently', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  instance._token_cache_file = () => { throw new Error('No agent: no disk access'); };
  const socket = process.env.SSH_AUTH_SOCK;
  const original = console.error;
  const messages = [];
  try {
    delete process.env.SSH_AUTH_SOCK;
    instance.rc.token_cache = false;
    console.error = (...args) => messages.push(format(...args));
    assert.equal(await instance.connect(), 'fresh-token');
  } finally {
    process.env.SSH_AUTH_SOCK = socket;
    console.error = original;
  }
  assert.equal(fs.existsSync(file), false);
  assert.equal(fs.existsSync(file + '.next'), false);
  assert.ok(!messages.some(message => message.includes('token not persisted')));
  assert.ok(!messages.join('\n').includes('fresh-token'));
});

test('without an SSH agent existing armor is left untouched', async t => {
  const {client, seed, file} = await fixture(t);
  const instance = client();
  await seed(instance);
  const before = fs.readFileSync(file, 'utf8');
  const socket = process.env.SSH_AUTH_SOCK;
  try {
    delete process.env.SSH_AUTH_SOCK;
    instance.rc.token_cache = false;
    await instance._save_cached_token('replacement-token', {lease_duration : 86400, renewable : true});
  } finally {
    process.env.SSH_AUTH_SOCK = socket;
  }
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.existsSync(file + '.next'), false);
});


test('constructor disables token caching when no SSH agent is configured', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.rc, token_cache : true}));
  const module_path = path.resolve(__dirname, '..', 'index.js');
  const script = `const Vauth = require(${JSON.stringify(module_path)});
    const instance = new Vauth();
    process.stdout.write(String(instance.rc.token_cache));
    instance.login().catch(() => process.exit(1));`;
  const output = await exec(process.execPath, ['-e', script], {
    cwd : home,
    env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
  });
  assert.equal(output.stdout.trim(), 'false');
  assert.ok(!output.stderr.includes('token not persisted'));
  assert.equal(fs.existsSync(file), false);
});


for(const selected of ['identity', 'mail', 'default']) {
  test(`cache encryption selects ${selected}; decryption uses embedded fingerprint`, async t => {
    const {client, file} = await fixture(t);
    const instance = client();
    const directory = path.dirname(path.dirname(path.dirname(file)));
    const key = path.join(directory, 'selected-key');
    const comment = 'selected-cache@test';
    assert.equal(spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', key]).status, 0);
    assert.equal(spawnSync('ssh-add', [key]).status, 0);
    try {
      if(selected === 'identity') {
        process.env.VAUTH_USER_IDENTITY = comment;
        process.env.VAUTH_USER_MAIL = 'missing-key@test';
      } else if(selected === 'mail') {
        process.env.VAUTH_USER_MAIL = comment;
      }
      assert.equal(await instance.connect(), 'fresh-token');
      const fingerprint = spawnSync('ssh-keygen', ['-lf', key + '.pub'], {encoding : 'utf8'}).stdout.split(/\s+/)[1];
      const armor = fs.readFileSync(file, 'utf8');
      assert.equal(armor.startsWith(`ssh-agent-crypt:v3:${fingerprint}.`), selected !== 'default');
      delete process.env.VAUTH_USER_IDENTITY;
      delete process.env.VAUTH_USER_MAIL;
      assert.equal(await client().connect(), 'fresh-token');
    } finally {
      spawnSync('ssh-add', ['-d', key]);
      delete process.env.VAUTH_USER_IDENTITY;
      delete process.env.VAUTH_USER_MAIL;
    }
  });
}

test('Windows keeps cache enabled and selects Pageant without SSH_AUTH_SOCK', async t => {
  const {client, file} = await fixture(t);
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, 'foundry.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : client().VAULT_ADDR, ssh_auth : {role : 'windows-role'}}));
  const module_path = path.resolve(__dirname, '..', 'index.js');
  const script = `const Vauth = require(${JSON.stringify(module_path)});
    Object.defineProperty(process, 'platform', {value: 'win32'});
    const instance = new Vauth();
    const result = {cacheDisabled: instance.rc.token_cache === false, role: instance.rc.ssh_auth.role};
    instance._read_token_cache = async () => undefined;
    instance._save_cached_token = async () => {};
    instance._login_vault_ssh = async (auth, agent) => {
      result.agent = agent;
      return {client_token: 'windows-test-token', lease_duration: 86400, renewable: true};
    };
    instance.connect().then(() => process.stdout.write(JSON.stringify(result))).catch(() => process.exit(1));`;
  const output = await exec(process.execPath, ['-e', script], {
    cwd : home,
    env : {...process.env, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
  });
  assert.deepEqual(JSON.parse(output.stdout), {cacheDisabled : false, role : 'windows-role', agent : 'pageant'});
});


for(const command of [[], ['login'], ['connect']]) {
  test(`standalone CLI ${JSON.stringify(command)} outputs a token and reuses cache`, async t => {
    const {client, file, requests} = await fixture(t);
    const instance = client();
    const home = path.dirname(path.dirname(path.dirname(file)));
    const rc = path.join(home, '.vauthrc');
    fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.rc, env : {map : {'INVALID;NAME' : 'ignored'}}}));
    const cli = path.resolve(__dirname, '..', 'index.js');
    const env = {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : ''};
    const initial = await exec(process.execPath, [cli, ...command, '--renew'], {cwd : home, env});
    assert.equal(initial.stdout, 'fresh-token');
    assert.match(initial.stderr, /^Vauth token: generated · 1d\n$/);
    const armor = fs.readFileSync(file, 'utf8');
    assert.match(armor, /^ssh-agent-crypt:v3:/);
    const reused = await exec(process.execPath, [cli, ...command], {cwd : home, env});
    assert.equal(reused.stdout, initial.stdout);
    assert.match(reused.stderr, /^Vauth token: reused · /);
    assert.equal(fs.readFileSync(file, 'utf8'), armor);
    assert.deepEqual(requests.map(r => r.path), ['/v1/auth/jwt/login']);
    const source = await exec(process.execPath, [cli, ...command, '--source'], {cwd : home, env});
    assert.equal(source.stdout, "export VAULT_TOKEN='fresh-token'\n");
    const json = await exec(process.execPath, [cli, ...command, '--ir://json'], {cwd : home, env});
    assert.equal(JSON.parse(json.stdout), 'fresh-token');
    assert.ok(!source.stderr.includes('fresh-token'));
  });
}

test('constructor ignores unrelated configuration and expands authentication macros only', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-rc-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const rc = path.join(directory, '.vauthrc');
  fs.writeFileSync(rc, 'vault_addr: https://vault.example.test\nssh_auth: {role: "$${env.TEST_AUTH_ROLE}"}\nenv: {map: "not a mapping", gitlab: true}\nssh-agent-crypt: [ignored, "$${env.MISSING}"]\n');
  const script = `const V = require(${JSON.stringify(path.resolve(__dirname, '..', 'index.js'))}); const v = new V(); process.stdout.write(JSON.stringify(v.rc));`;
  const out = await exec(process.execPath, ['-e', script], {cwd : directory, env : {...process.env, VAUTHRC : rc, TEST_AUTH_ROLE : 'role-test'}});
  assert.deepEqual(JSON.parse(out.stdout), {vault_addr : 'https://vault.example.test', ssh_auth : {role : 'role-test'}});
});

test('public lookupSelf and transport expose token metadata without profile reads', async t => {
  const {client, requests} = await fixture(t);
  const v = client();
  const token = await v.connect();
  const metadata = await v.lookupSelf(token);
  assert.equal(metadata.entity_id, 'test-entity');
  assert.equal(metadata.ttl, 12 * HOUR);
  assert.equal(metadata.lease_duration, 24 * HOUR);
  assert.equal(v.vaultURL('/auth/token/lookup-self'), v.VAULT_ADDR + '/v1/auth/token/lookup-self');
  assert.deepEqual(requests.map(r => r.path), ['/v1/auth/jwt/login', '/v1/auth/token/lookup-self']);
});

test('transport never follows redirects or leaks the token in HTTPError', async t => {
  const {client, requests} = await fixture(t);
  const v = client();
  const redirect = http.createServer((req, res) => { res.writeHead(302, {location : v.VAULT_ADDR + '/v1/auth/token/lookup-self'}); res.end('secret-server-response'); });
  await new Promise(resolve => redirect.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => redirect.close(resolve)));
  v.VAULT_ADDR = `http://127.0.0.1:${redirect.address().port}`;
  await assert.rejects(v.request('GET', 'redirect', 'secret-token'), err => {
    assert.ok(err instanceof Vauth.HTTPError);
    assert.equal(err.status, 302);
    assert.equal(err.body, 'secret-server-response');
    assert.ok(!String(err).includes('secret'));
    return true;
  });
  assert.deepEqual(requests, []);
});

test('transport deadline includes a stalled response body', async t => {
  const server = http.createServer((req, res) => { res.writeHead(200); res.write('{'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const v = Object.create(Vauth.prototype);
  v.VAULT_ADDR = `http://127.0.0.1:${server.address().port}`;
  v.requestTimeout = 30;
  await assert.rejects(v.request('GET', 'stall'), err => err.code === 'ETIMEDOUT');
});

test('cnyks runs version, generates help and reports unknown commands', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-version-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const cli = path.resolve(__dirname, '..', 'index.js');
  const options = {cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : '', VAULT_ADDR : '', VAULT_TOKEN : ''}};
  for(const command of [['version'], ['--version'], ['--ir://run=version']]) {
    const out = await exec(process.execPath, [cli, ...command], options);
    assert.equal(out.stdout.trim(), require('../package.json').version);
    assert.equal(out.stderr, '');
  }
  for(const command of [['--help'], ['help'], ['?'], ['runner:list_commands']]) {
    const help = await exec(process.execPath, [cli, ...command], options);
    assert.equal(help.stdout, '');
    assert.match(help.stderr, /commands list/);
    assert.match(help.stderr, /login/);
    assert.match(help.stderr, /connect/);
    assert.match(help.stderr, /version/);
  }
  await assert.rejects(exec(process.execPath, [cli, 'unknown-command'], options));
  await assert.rejects(exec(process.execPath, [cli], options));
});

test('CLI errors do not print server response bodies or inherited tokens', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-error-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const server = http.createServer((req, res) => { res.writeHead(503); res.end('secret-server-response'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const rc = path.join(directory, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : `http://127.0.0.1:${server.address().port}`, jwt_auth : {jwt : 'secret-jwt'}, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'index.js');
  await assert.rejects(exec(process.execPath, [cli], {
    cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : rc, VAULT_TOKEN : 'secret-token'},
  }), err => {
    assert.equal(err.stdout, '');
    assert.ok(!err.stderr.includes('secret-server-response'));
    assert.ok(!err.stderr.includes('secret-token'));
    assert.ok(!err.stderr.includes('secret-jwt'));
    return true;
  });
});

test('transport deadline cancels a request waiting for response headers', async t => {
  const server = http.createServer(() => {});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const v = Object.create(Vauth.prototype);
  v.VAULT_ADDR = `http://127.0.0.1:${server.address().port}`;
  v.requestTimeout = 30;
  await assert.rejects(v.request('GET', 'stall'), err => err.code === 'ETIMEDOUT');
});

test('transport forwards method, token and JSON payload and returns explicit statuses', async t => {
  const {client, requests} = await fixture(t);
  const v = client();
  const payload = {message : 'écho'};
  const response = await v.request('PUT', 'write', 'fixture-token', payload, 0);
  assert.equal(response.status, 404);
  assert.ok(Buffer.isBuffer(response.body));
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'PUT');
  assert.equal(requests[0].token, 'fixture-token');
  assert.deepEqual(JSON.parse(requests[0].body), payload);
});

test('HTTPError keeps the response available to SDK callers while logs show status', () => {
  const error = new Vauth.HTTPError(503, 'secret-server-response');
  assert.equal(error.body, 'secret-server-response');
  assert.equal(error.status, 503);
  assert.ok(!require('util').inspect(error).includes('secret-server-response'));
  assert.ok(!JSON.stringify(error).includes('secret-server-response'));
});

test('cnyks static version works with a malformed configuration file', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-static-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  fs.writeFileSync(path.join(directory, '.vauthrc'), 'vault_addr: [');
  const cli = path.resolve(__dirname, '..', 'index.js');
  const options = {cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : ''}};
  for(const command of [['version'], ['--version'], ['--ir://run=version']]) {
    const result = await exec(process.execPath, [cli, ...command], options);
    assert.equal(result.stdout, require('../package.json').version);
    assert.equal(result.stderr, '');
  }
});
