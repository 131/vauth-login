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

// Construction uses an isolated file/environment; the production constructor
// has no testing-only configuration knobs.
function configuredClient(t, document, overrides = {}, construct = Client => new Client()) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-config-'));
  t.after(() => fs.rmSync(home, {recursive : true, force : true}));
  const file = path.join(home, '.vauthrc');
  fs.writeFileSync(file, JSON.stringify(document));
  const env = {HOME : home, USERPROFILE : home, VAUTHRC : file, VAULT_ADDR : '', VAULT_TOKEN : '', ...overrides};
  const previous = {};
  for(const key of Object.keys(env)) { previous[key] = process.env[key]; process.env[key] = env[key]; }
  let client;
  const module = require.resolve('../index');
  const cached = require.cache[module];
  delete require.cache[module];
  try { client = construct(require('../index')); } finally {
    require.cache[module] = cached;
    for(const key of Object.keys(env)) {
      if(previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  }
  return client;
}


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
  const client = (settings = {}) => {
    const rc = {vault_addr : `http://127.0.0.1:${server.address().port}`, jwt_auth : {path : 'jwt', jwt : 'test-jwt', role : 'test-role'}, ...settings.rc};
    if(settings.noAuth) delete rc.jwt_auth;
    const instance = configuredClient(t, rc, {VAULT_TOKEN : settings.token || '', ...settings.env});
    instance._token_cache_file = () => path.join(directory, '.vauth', 'tokens', instance._token_cache_key() + '.creds');
    if(settings.timeout !== undefined) instance.requestTimeout = settings.timeout;
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
  assert.equal(await first.Connect(), 'fresh-token');
  assert.equal((await read(first)).token, 'fresh-token');
  assert.ok((await read(first)).expires_at > Date.now() + 23 * HOUR * 1000);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const second = client();
  assert.equal(await second.Connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), [path.basename(file)]);
});

test('a token in the last third of its lease is renewed and saved', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : HOUR});
  const instance = client();
  await seed(instance, 12 * HOUR);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].token, 'cached-token');
  assert.ok((await read(instance)).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('more than one third remaining does not trigger renewal', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : 4 * HOUR + 1});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.equal(requests.length, 0);
});

test('expired cached tokens are replaced with a new persisted login', async t => {
  const {client, seed, read, requests, file} = await fixture(t);
  const instance = client();
  await seed(instance);
  const cache = (await readCache(file));
  cache.expires_at = Date.now() - 1000;
  await writeCache(file, cache);
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal((await read(instance)).token, 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('cached tokens are reused without checking revocation', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 403});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.deepEqual(requests, []);
  await assert.rejects(instance.LookupSelf(instance.VAULT_TOKEN));
});

test('nonrenewable tokens nearing expiry trigger reauthentication', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renewable : false});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

for(const status of [400, 403]) {
  test(`rejected renewal (${status}) triggers a new persisted login`, async t => {
    const {client, seed, read, requests} = await fixture(t, {ttl : HOUR, renew_status : status});
    const instance = client();
    await seed(instance);
    assert.equal(await instance.Connect(), 'fresh-token');
    assert.equal((await read(instance)).token, 'fresh-token');
    assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self', '/v1/auth/jwt/login']);
  });
}

test('server failures do not generate extra tokens, and connect can be retried', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  await seed(instance);
  await assert.rejects(instance.Connect());
  await assert.rejects(instance.Connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self', '/v1/auth/token/renew-self']);
  assert.equal((await read(instance)).token, 'cached-token');
});

test('renewal server failures do not generate extra tokens', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  await seed(instance);
  await assert.rejects(instance.Connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
});

test('an inherited environment token is returned as is: no lookup, no renewal, no cache write', async t => {
  const {client, seed, read, requests, file} = await fixture(t, {ttl : HOUR});
  const instance = client({token : 'environment-token'});
  await seed(instance);
  const before = fs.readFileSync(file, 'utf8');

  instance._read_token_cache = async () => { throw new Error('Inherited token: no cache lookup'); };
  let token;
  const lines = await captureStatusAsync(async () => { token = await instance.Connect(); });
  assert.equal(token, 'environment-token');
  assert.deepEqual(lines, ['Vauth token: inherited']);
  assert.deepEqual(requests, []);
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal((await read(instance)).token, 'cached-token');
});

test('an inherited token is returned even without an authentication method or configuration', async t => {
  const {client, requests} = await fixture(t);
  const instance = client({token : 'environment-token', noAuth : true});


  assert.equal(await instance.Connect(), 'environment-token');
  assert.deepEqual(requests, []);
});

test('nonexpiring tokens are reused without renewal', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : 0});
  const instance = client();
  await seed(instance, 0);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.equal((await read(instance)).expires_at, null);
  assert.equal(requests.length, 0);
});

test('corrupt caches are replaced with a valid cache', async t => {
  const {client, read, file} = await fixture(t);
  fs.mkdirSync(path.dirname(file), {recursive : true});
  fs.writeFileSync(file, '{broken');
  const instance = client();
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal((await read(instance)).token, 'fresh-token');
});

test('cache entries are isolated by Vault address and authentication configuration', async t => {
  const {client, seed, read, file} = await fixture(t);
  const first = client();
  await seed(first);
  const second = client({rc : {jwt_auth : {path : 'jwt', jwt : 'test-jwt', role : 'other-role'}}});
  assert.equal(await second.Connect(), 'fresh-token');
  assert.notEqual(first._token_cache_file(), second._token_cache_file());
  assert.equal((await read(first)).token, 'cached-token');
  assert.equal((await read(second)).token, 'fresh-token');
  const third = client({rc : {vault_addr : 'http://other-vault.test'}});
  assert.notEqual(third._token_cache_key(), first._token_cache_key());
  assert.equal(fs.readdirSync(path.dirname(file)).length, 2);
  assert.ok(!fs.readFileSync(file, 'utf8').includes('test-jwt'));
});

test('repeated connect calls reuse the established connection', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(requests.length, 1);
});

test('an unwritable cache does not prevent login', async t => {
  const {client, file} = await fixture(t);
  fs.mkdirSync(path.dirname(path.dirname(file)), {recursive : true});
  fs.writeFileSync(path.dirname(file), 'not a directory');
  assert.equal(await client().Connect(), 'fresh-token');
});

test('without an auth method caches are ignored and --renew drops the inherited token', async t => {
  const {client, seed, requests} = await fixture(t);
  let instance = client({noAuth : true});
  await seed(instance);
  instance._read_token_cache = async () => { throw new Error('No auth: no cache lookup'); };
  assert.equal(await instance.Connect(), undefined);
  assert.equal(instance.VAULT_TOKEN, undefined);
  instance = client({token : 'uncached-token', noAuth : true});
  assert.equal(await instance.Connect(true), undefined);
  assert.equal(instance.VAULT_TOKEN, undefined);
  assert.deepEqual(requests, []);
});

test('--renew ignores both environment and cached tokens and saves a new token', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client({token : 'environment-token'});
  await seed(instance);

  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal((await read(instance)).token, 'fresh-token');
  assert.ok((await read(instance)).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('--renew replaces the token of a previously connected instance', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  await seed(instance);
  await instance.Connect();
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal((await read(instance)).token, 'fresh-token');
});

test('each successive --renew call forces a new login', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.equal(requests.length, 2);
});

test('--renew without an authentication method remains a no-op', async t => {
  const {client} = await fixture(t);
  const instance = client({noAuth : true});

  assert.equal(await instance.Connect(true), undefined);
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

async function captureStatusAsync(callback) {
  const lines = [];
  const original = console.error;
  console.error = (...args) => lines.push(format(...args));
  try {
    await callback();
  } finally {
    console.error = original;
  }
  return lines;
}

test('token status uses humanDiff with two significant units', () => {
  const instance = Object.create(Vauth.prototype);
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
    await instance.Connect();
    await instance.Connect();
    const validity = options.duration ? `valid for ${options.duration}` : 'valid indefinitely';
    assert.deepEqual(calls, [`Vauth token: ${options.operation} · ${validity.replace(/^valid for /, '')}`]);
  });
}

test('failed connections never announce successful token status', async t => {
  const {client, seed} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  await seed(instance);
  const calls = [];
  instance._token_status = operation => calls.push(operation);
  await assert.rejects(instance.Connect());
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
    await instance.Connect();
    assert.equal(requests.some(req => req.path.endsWith('/renew-self')), renew);
    assert.equal((await read(instance)).lease_duration, renew ? 24 * HOUR : lease);
  });
}

test('lookups never reset the original lease duration', async t => {
  const options = {ttl : 20 * HOUR};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  await seed(instance, 24 * HOUR);
  await instance.Connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 12 * HOUR);
  await client().Connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 8 * HOUR);
  await client().Connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 1);
});

test('renewal updates the lease baseline to the newly granted duration', async t => {
  const options = {ttl : 20 * 60};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  await seed(instance, HOUR);
  await instance.Connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 8 * HOUR);
  await client().Connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 2);
});

test('normal reuse never writes the token cache', async t => {
  const {client, seed, file, requests} = await fixture(t);
  const instance = client({token : 'cached-token'});
  await seed(instance);

  const before = fs.readFileSync(file, 'utf8');
  const stat = fs.statSync(file);
  instance._save_cached_token = () => { throw new Error('Reuse must not write'); };
  assert.equal(await instance.Connect(), 'cached-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.statSync(file).ino, stat.ino);
  assert.equal(fs.statSync(file).mtimeMs, stat.mtimeMs);
  assert.deepEqual(requests, []);
});


test('lookup returns the lease duration and preserves a cached renewal baseline', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, creation_ttl : 24 * HOUR});
  const instance = client();
  const uncached = await instance.LookupSelf('environment-token');
  assert.equal(uncached.lease_duration, 24 * HOUR);
  assert.equal(uncached.ttl, HOUR);
  await seed(instance, 12 * HOUR);
  const cached = await instance.LookupSelf('cached-token');
  assert.equal(cached.lease_duration, 12 * HOUR);
  assert.equal(requests.length, 2);
});

test('token_cache false skips all cache filesystem access', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client({rc : {token_cache : false}});

  instance._token_cache_file = () => { throw new Error('Disabled cache must not access disk'); };
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(fs.existsSync(file), false);
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('token_cache false ignores existing tokens on disk without deleting them', async t => {
  const {client, seed, requests, file} = await fixture(t);
  await seed(client());
  const instance = client({rc : {token_cache : false}});
  const before = fs.readFileSync(file, 'utf8');

  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  const second = client({rc : {token_cache : false}});
  assert.equal(await second.Connect(), 'fresh-token');
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('token_cache false still returns an environment token without any request or persistence', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client({token : 'environment-token', rc : {token_cache : false}});


  assert.equal(await instance.Connect(), 'environment-token');
  assert.deepEqual(requests, []);
  assert.equal(fs.existsSync(file), false);
});

test('real CLI reads token_cache false from .vauthrc', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  for(let i = 0; i < 2; i++) {
    const output = await exec(process.execPath, [cli], {
      cwd : home,
      env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : process.env.SSH_AUTH_SOCK},
    });
    assert.equal(output.stdout, 'fresh-token');
    assert.ok(output.stderr.includes('Vauth token: generated'));
  }
  assert.equal(fs.existsSync(file), false);
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('disk cache contains only armor, interoperable with ssh-agent-crypt CLI', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  await instance.Connect();
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
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.match(fs.readFileSync(file, 'utf8'), /^ssh-agent-crypt:v3:/);
});

test('without an SSH agent cache is skipped silently', async t => {
  const {client, file} = await fixture(t);
  const instance = client({rc : {token_cache : false}});
  instance._token_cache_file = () => { throw new Error('No agent: no disk access'); };
  const socket = process.env.SSH_AUTH_SOCK;
  const original = console.error;
  const messages = [];
  try {
    delete process.env.SSH_AUTH_SOCK;

    console.error = (...args) => messages.push(format(...args));
    assert.equal(await instance.Connect(), 'fresh-token');
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
  await seed(client());
  const instance = client({env : {SSH_AUTH_SOCK : ''}});
  const before = fs.readFileSync(file, 'utf8');
  const socket = process.env.SSH_AUTH_SOCK;
  try {
    delete process.env.SSH_AUTH_SOCK;

    await instance._save_cached_token('replacement-token', {lease_duration : 86400, renewable : true});
  } finally {
    process.env.SSH_AUTH_SOCK = socket;
  }
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.existsSync(file + '.next'), false);
});


// A project-selected Vault must be allowed by ~/.vauthrc or VAULT_ADDR.
async function projectVault(t, options = {}) {
  const {client, file, requests, seed} = await fixture(t, options);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const project = path.join(home, 'project');
  fs.mkdirSync(project);
  const rc = {vault_addr : instance.VAULT_ADDR, ...instance.RC, ...(options.rc || {})};
  fs.writeFileSync(path.join(project, '.vauthrc'), JSON.stringify(rc));
  if(options.home)
    fs.writeFileSync(path.join(home, '.vauthrc'), JSON.stringify(options.home(instance.VAULT_ADDR)));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  const run = async script => {
    try {
      const output = await exec(process.execPath, script ? ['-e', script] : [cli, ...(options.args || [])], {
        cwd : project, env : {...process.env, HOME : home, VAUTHRC : '', VAULT_TOKEN : '', VAULT_ADDR : options.envAddr ? options.envAddr(instance.VAULT_ADDR) : ''},
      });
      return {code : 0, ...output};
    } catch(err) {
      return {code : err.code, stdout : err.stdout, stderr : err.stderr};
    }
  };
  // A terminal must not change the allowlist decision.
  const tty = `process.stdin.isTTY = true;
    const Vauth = require(${JSON.stringify(path.resolve(__dirname, '..', 'index.js'))});
    new Vauth().Connect().then(token => process.stdout.write(token), err => { console.error(err.message); process.exit(1); });`;
  return {instance, run, tty, requests, seed, file, addr : instance.VAULT_ADDR};
}

for(const flag of ['--accept', '--accept=false']) {
  test(`removed ${flag} is rejected before any request`, async t => {
    const {run, requests} = await projectVault(t, {rc : {token_cache : false}, args : [flag]});
    const result = await run();
    assert.notEqual(result.code, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /Usage: vauth-login/);
    assert.deepEqual(requests, []);
  });
}

test('a project vault matching environment VAULT_ADDR is allowed without a home config', async t => {
  const {run, requests} = await projectVault(t, {rc : {token_cache : false}, envAddr : addr => addr + '/'});
  const result = await run();
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, 'fresh-token');
  assert.ok(!result.stderr.includes('Unknown vault'));
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('environment VAULT_ADDR does not trust a different project vault', async t => {
  const {run, requests} = await projectVault(t, {rc : {token_cache : false}, envAddr : () => 'https://other.example.test'});
  const result = await run();
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, '');
  assert.ok(result.stderr.includes('Unknown vault'));
  assert.deepEqual(requests, []);
});

test('a project .vauthrc selecting an unknown vault is refused without a terminal, before any request', async t => {
  const {run, requests, addr} = await projectVault(t, {rc : {token_cache : false}});
  const result = await run();
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, '');
  assert.ok(result.stderr.includes(`Unknown vault ${addr}, selected by `));
  assert.ok(result.stderr.includes('known_vaults'));
  assert.ok(!result.stderr.includes('test-jwt'));
  assert.deepEqual(requests, []);
});

test('an unknown project vault is refused on a terminal without a dialogue', async t => {
  const {run, tty, requests} = await projectVault(t, {rc : {token_cache : false}});
  const result = await run(tty);
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Unknown vault/);
  assert.ok(!result.stderr.includes('Continue?'));
  assert.deepEqual(requests, []);
});

for(const [label, home] of [
  ['vault_addr', addr => ({vault_addr : addr + '/'})],
  ['known_vaults', addr => ({known_vaults : ['https://other.example.test', addr + '/']})],
]) {
  test(`a project vault listed by ~/.vauthrc ${label} is allowed`, async t => {
    const {run, requests} = await projectVault(t, {rc : {token_cache : false}, home});
    const result = await run();
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stdout, 'fresh-token');
    assert.ok(!result.stderr.includes('Unknown vault'));
    assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  });
}

test('a valid cached token for an unknown project vault is reused offline', async t => {
  const {run, instance, seed, requests} = await projectVault(t);
  await seed(instance);
  const result = await run();
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout, 'cached-token');
  assert.ok(!result.stderr.includes('Unknown vault'));
  assert.deepEqual(requests, []);
});

test('renewing a cached token for an unknown project vault is refused', async t => {
  const {run, instance, seed, requests} = await projectVault(t, {ttl : HOUR});
  await seed(instance);
  const result = await run();
  assert.notEqual(result.code, 0);
  assert.ok(result.stderr.includes('Unknown vault'));
  assert.deepEqual(requests, []);
});

test('constructor disables token caching when no SSH agent is configured', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC, token_cache : true}));
  const module_path = path.resolve(__dirname, '..', 'index.js');
  const script = `const Vauth = require(${JSON.stringify(module_path)});
    const instance = new Vauth();
    process.stdout.write(String(instance.RC.token_cache));
    instance.Connect().catch(() => process.exit(1));`;
  const output = await exec(process.execPath, ['-e', script], {
    cwd : home,
    env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
  });
  assert.equal(output.stdout.trim(), 'true');
  assert.ok(!output.stderr.includes('token not persisted'));
  assert.equal(fs.existsSync(file), false);
});


for(const selected of ['identity', 'mail', 'default']) {
  test(`cache encryption selects ${selected}; decryption uses embedded fingerprint`, async t => {
    const {client, file} = await fixture(t);
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
      const instance = client();
      assert.equal(await instance.Connect(), 'fresh-token');
      const fingerprint = spawnSync('ssh-keygen', ['-lf', key + '.pub'], {encoding : 'utf8'}).stdout.split(/\s+/)[1];
      const armor = fs.readFileSync(file, 'utf8');
      assert.equal(armor.startsWith(`ssh-agent-crypt:v3:${fingerprint}.`), selected !== 'default');
      delete process.env.VAUTH_USER_IDENTITY;
      delete process.env.VAUTH_USER_MAIL;
      assert.equal(await client().Connect(), 'fresh-token');
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
    const result = {cacheDisabled: instance.RC.token_cache === false, role: instance.RC.ssh_auth.role};
    instance._read_token_cache = async () => undefined;
    instance._save_cached_token = async () => {};
    instance._login_vault_ssh = async (auth, agent) => {
      result.agent = agent;
      return {client_token: 'windows-test-token', lease_duration: 86400, renewable: true};
    };
    instance.Connect().then(() => process.stdout.write(JSON.stringify(result))).catch(() => process.exit(1));`;
  const output = await exec(process.execPath, ['-e', script], {
    cwd : home,
    env : {...process.env, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
  });
  assert.deepEqual(JSON.parse(output.stdout), {cacheDisabled : false, role : 'windows-role', agent : 'pageant'});
});


test('standalone CLI outputs a token and reuses cache', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC, env : {map : {'INVALID;NAME' : 'ignored'}}}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  const env = {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : ''};
  const initial = await exec(process.execPath, [cli, '--renew'], {cwd : home, env});
  assert.equal(initial.stdout, 'fresh-token');
  assert.match(initial.stderr, /^Vauth token: generated · 1d\n$/);
  const armor = fs.readFileSync(file, 'utf8');
  assert.match(armor, /^ssh-agent-crypt:v3:/);
  const reused = await exec(process.execPath, [cli], {cwd : home, env});
  assert.equal(reused.stdout, initial.stdout);
  assert.match(reused.stderr, /^Vauth token: reused · /);
  assert.equal(fs.readFileSync(file, 'utf8'), armor);
  assert.deepEqual(requests.map(r => r.path), ['/v1/auth/jwt/login']);
});

test('constructor ignores unrelated configuration and expands authentication macros only', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-rc-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const rc = path.join(directory, '.vauthrc');
  fs.writeFileSync(rc, 'vault_addr: https://vault.example.test\nssh_auth: {role: "$${env.TEST_AUTH_ROLE}"}\nenv: {map: "not a mapping", gitlab: true}\nssh-agent-crypt: [ignored, "$${env.MISSING}"]\n');
  const script = `const V = require(${JSON.stringify(path.resolve(__dirname, '..', 'index.js'))}); const v = new V(); process.stdout.write(JSON.stringify(v.RC));`;
  const out = await exec(process.execPath, ['-e', script], {cwd : directory, env : {...process.env, VAUTHRC : rc, TEST_AUTH_ROLE : 'role-test'}});
  assert.deepEqual(JSON.parse(out.stdout), {vault_addr : 'https://vault.example.test', ssh_auth : {role : '$${env.TEST_AUTH_ROLE}'}, env : {map : 'not a mapping', gitlab : true}, 'ssh-agent-crypt' : ['ignored', '$${env.MISSING}']});
});

test('public lookupSelf and transport expose token metadata without profile reads', async t => {
  const {client, requests} = await fixture(t);
  const v = client();
  const token = await v.Connect();
  const metadata = await v.LookupSelf(token);
  assert.equal(metadata.entity_id, 'test-entity');
  assert.equal(metadata.ttl, 12 * HOUR);
  assert.equal(metadata.lease_duration, 24 * HOUR);
  assert.equal(v._vault_url('/auth/token/lookup-self'), v.VAULT_ADDR + '/v1/auth/token/lookup-self');
  assert.deepEqual(requests.map(r => r.path), ['/v1/auth/jwt/login', '/v1/auth/token/lookup-self']);
});

test('transport never follows redirects or leaks the token in HTTPError', async t => {
  const {client, requests} = await fixture(t);
  let v = client();
  const redirect = http.createServer((req, res) => { res.writeHead(302, {location : v.VAULT_ADDR + '/v1/auth/token/lookup-self'}); res.end('secret-server-response'); });
  await new Promise(resolve => redirect.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => redirect.close(resolve)));
  v = client({rc : {vault_addr : `http://127.0.0.1:${redirect.address().port}`}});
  await assert.rejects(v.Request('GET', 'redirect', 'secret-token'), err => {
    assert.ok(err instanceof v.constructor.HTTPError);
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
  const v = configuredClient(t, {vault_addr : `http://127.0.0.1:${server.address().port}`});
  v.requestTimeout = 30;
  await assert.rejects(v.Request('GET', 'stall'), err => err.code === 'ETIMEDOUT');
});

test('CLI fails when no authentication method can produce a token', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-unbound-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  for(const args of [[], ['--renew']]) {
    const env = {...process.env, HOME : directory, VAUTHRC : '', VAULT_ADDR : '', VAULT_TOKEN : args.length ? 'secret-token' : ''};
    await assert.rejects(exec(process.execPath, [cli, ...args], {cwd : directory, env}), err => {
      assert.equal(err.code, 1);
      assert.equal(err.stdout, '');
      assert.match(err.stderr, /no authentication method available/);
      assert.ok(!err.stderr.includes('secret-token'));
      return true;
    });
  }
});

test('CLI errors do not print server response bodies or inherited tokens', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-error-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const server = http.createServer((req, res) => { res.writeHead(503); res.end('secret-server-response'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const rc = path.join(directory, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : `http://127.0.0.1:${server.address().port}`, jwt_auth : {jwt : 'secret-jwt'}, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  await assert.rejects(exec(process.execPath, [cli, '--renew'], {
    cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : rc, VAULT_TOKEN : 'secret-token'},
  }), err => {
    assert.equal(err.stdout, '');
    assert.ok(!err.stderr.includes('secret-server-response'));
    assert.ok(!err.stderr.includes('secret-token'));
    assert.ok(!err.stderr.includes('secret-jwt'));
    return true;
  });
});

test('CLI returns an inherited token as is, announcing it on stderr only', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-inherited-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const server = http.createServer((req, res) => { res.writeHead(503); res.end('unreachable'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const rc = path.join(directory, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : `http://127.0.0.1:${server.address().port}`, jwt_auth : {jwt : 'secret-jwt'}, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  const {stdout, stderr} = await exec(process.execPath, [cli], {
    cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : rc, VAULT_TOKEN : 'inherited-token'},
  });
  assert.equal(stdout, 'inherited-token');
  assert.equal(stderr, 'Vauth token: inherited\n');
});

test('transport deadline cancels a request waiting for response headers', async t => {
  const server = http.createServer(() => {});
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const v = configuredClient(t, {vault_addr : `http://127.0.0.1:${server.address().port}`});
  v.requestTimeout = 30;
  await assert.rejects(v.Request('GET', 'stall'), err => err.code === 'ETIMEDOUT');
});

test('transport forwards method, token and JSON payload and returns explicit statuses', async t => {
  const {client, requests} = await fixture(t);
  const v = client();
  const payload = {message : 'écho'};
  const response = await v.Request('PUT', 'write', 'fixture-token', payload, 0);
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



test('CLI rejects SDK methods and unknown flags before using inherited credentials', async t => {
  const {run, requests} = await projectVault(t, {rc : {token_cache : false}});
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  // The project file is deliberately malformed: argument rejection must precede
  // configuration parsing as well as any request or token output.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-args-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  fs.writeFileSync(path.join(directory, '.vauthrc'), 'vault_addr: [');
  const options = {cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : '', VAULT_TOKEN : 'secret-token'}};
  for(const args of [['lookupSelf'], ['request', 'GET', 'auth/token/lookup-self'], ['vaultURL'], ['runner:list_commands'], ['--ir://run=lookupSelf'], ['--ir://raw'], ['--foo'], ['--renew=maybe'], ['--renew=true'], ['--renew=false'], ['login'], ['connect'], ['version'], ['help'], ['login', 'extra']]) {
    await assert.rejects(exec(process.execPath, [cli, ...args], options), err => {
      assert.equal(err.code, 1);
      assert.equal(err.stdout, '');
      assert.match(err.stderr, /Usage: vauth-login/);
      assert.ok(!err.stderr.includes('secret-token'));
      return true;
    });
  }
  // The normal unknown-project login still refuses before any request.
  const result = await run();
  assert.notEqual(result.code, 0);
  assert.deepEqual(requests, []);
});

test('only --renew forces login instead of returning inherited credentials', async t => {
  const {client, file, requests} = await fixture(t);
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : client().VAULT_ADDR, jwt_auth : {jwt : 'test-jwt', role : 'test-role'}, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  const options = {cwd : home, env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : 'inherited-token'}};
  const reused = await exec(process.execPath, [cli], options);
  assert.equal(reused.stdout, 'inherited-token');
  assert.equal(reused.stderr, 'Vauth token: inherited\n');
  assert.deepEqual(requests, []);
  const renewed = await exec(process.execPath, [cli, '--renew'], options);
  assert.equal(renewed.stdout, 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('npm executable points at the shipped standalone CLI', () => {
  const manifest = require('../package.json');
  assert.equal(manifest.bin['vauth-login'], './bin/vauth-login.js');
  assert.ok(manifest.files.includes('bin/vauth-login.js'));
});


test('Request rejects an unknown Vault before URL parsing or payload serialization', async t => {
  const instance = configuredClient(t, {vault_addr : 'not-a-url'});
  instance._safe_vault = false;
  const payload = {toJSON() { throw new Error('Payload must not be serialized'); }};
  await assert.rejects(instance.Request('POST', 'auth/jwt/login', '', payload), /Unknown vault/);
});

test('effective address and token getters cannot be reassigned', t => {
  const v = configuredClient(t, {}, {VAULT_ADDR : 'https://vault.example.test', VAULT_TOKEN : 'inherited-token'});
  assert.throws(() => { v.VAULT_ADDR = 'https://other.example.test'; }, TypeError);
  assert.throws(() => { v.VAULT_TOKEN = 'other-token'; }, TypeError);
  assert.equal(v.VAULT_ADDR, 'https://vault.example.test');
  assert.equal(v.VAULT_TOKEN, 'inherited-token');
});

test('CLI rejects SDK commands without sending inherited credentials', async t => {
  const {client, file, requests} = await fixture(t);
  const home = path.dirname(path.dirname(path.dirname(file)));
  const project = path.join(home, 'project');
  fs.mkdirSync(project);
  fs.writeFileSync(path.join(project, '.vauthrc'), JSON.stringify({vault_addr : client().VAULT_ADDR, jwt_auth : {jwt : 'test-jwt', role : 'test-role'}, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  const options = {cwd : project, env : {...process.env, HOME : home, VAUTHRC : '', VAULT_ADDR : '', VAULT_TOKEN : 'secret-token'}};
  for(const args of [['lookupSelf'], ['request', 'GET'], ['vaultURL']]) {
    await assert.rejects(exec(process.execPath, [cli, ...args], options), err => {
      assert.equal(err.stdout, '');
      assert.ok(!err.stderr.includes('secret-token'));
      assert.match(err.stderr, /Usage: vauth-login/);
      return true;
    });
  }
  assert.deepEqual(requests, []);
});


test('--version and --help do not load configuration or use inherited credentials', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vauth-login-info-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  fs.writeFileSync(path.join(directory, '.vauthrc'), 'vault_addr: [');
  fs.writeFileSync(path.join(directory, 'package.json'), '{');
  const cli = path.resolve(__dirname, '..', 'bin', 'vauth-login.js');
  const options = {cwd : directory, env : {...process.env, HOME : directory, VAUTHRC : '', VAULT_TOKEN : 'secret-token'}};
  for(const args of [['--version'], ['--renew', '--version']]) {
    const result = await exec(process.execPath, [cli, ...args], options);
    assert.equal(result.stdout, require('../package.json').version + '\n');
    assert.equal(result.stderr, '');
  }
  for(const args of [['--help'], ['--renew', '--version', '--help']]) {
    const result = await exec(process.execPath, [cli, ...args], options);
    assert.equal(result.stdout, 'Usage: vauth-login [--renew] [--version] [--help]\n');
    assert.equal(result.stderr, '');
  }
  await assert.rejects(exec(process.execPath, [cli, '--help', '--bogus'], options), err => {
    assert.equal(err.code, 1);
    assert.equal(err.stdout, '');
    assert.ok(!err.stderr.includes('secret-token'));
    return true;
  });
});


test('Node and Go expose one converged API without compatibility aliases', async t => {
  const {client, requests, file} = await fixture(t);
  const v = client();
  assert.equal(Vauth.Version(), require('../package.json').version);
  assert.deepEqual(Object.getOwnPropertyNames(Vauth.prototype).filter(name => name !== 'constructor' && !name.startsWith('_')).sort(),
    ['Connect', 'LookupSelf', 'RC', 'Request', 'VAULT_ADDR', 'VAULT_TOKEN']);
  assert.equal(Vauth.version, undefined);
  assert.equal(v._vault_url('/auth/token/lookup-self'), v.VAULT_ADDR + '/v1/auth/token/lookup-self');
  assert.equal(v._token_cache_file(), file);
  assert.equal(path.basename(file), v._token_cache_key() + '.creds');
  const token = await v.Connect();
  assert.equal(token, 'fresh-token');
  assert.equal(await v.Connect(), token);
  assert.equal((await v.LookupSelf()).entity_id, 'test-entity');
  const response = await v.Request('PUT', 'write', token, {value : 'test'}, 0);
  assert.equal(response.status, 404);
  assert.equal(requests.at(-1).method, 'PUT');
  assert.equal(requests.at(-1).token, token);
  assert.deepEqual(JSON.parse(requests.at(-1).body), {value : 'test'});
});

test('SDK transport rejects unknown project Vaults after offline token inheritance', async t => {
  const {client, file, requests} = await fixture(t);
  const home = path.dirname(path.dirname(path.dirname(file)));
  const project = path.join(home, 'sdk-project');
  fs.mkdirSync(project);
  const addr = client().VAULT_ADDR;
  fs.writeFileSync(path.join(project, '.vauthrc'), JSON.stringify({vault_addr : addr, jwt_auth : {jwt : 'test-jwt', role : 'test-role'}, token_cache : false}));
  const code = `
    const assert = require('node:assert/strict');
    const Vauth = require(${JSON.stringify(path.resolve(__dirname, '..', 'index.js'))});
    (async () => {
      const v = new Vauth();
      assert.equal(v._safe_vault, false);
      assert.equal(v.rc_file, undefined);
      assert.equal(await v.Connect(), 'inherited-token');
      assert.equal(v._vault_url('auth/token/lookup-self'), ${JSON.stringify(addr + '/v1/auth/token/lookup-self')});
      for(const call of [
        () => v.LookupSelf(),
        () => v.Request('GET', 'auth/token/lookup-self', 'inherited-token'),
        () => v.Request('POST', 'auth/jwt/login', '', {jwt: 'secret-jwt'}),
        () => v.Request('GET', 'identity/entity/id/test-entity'),
        () => v._renew_token('inherited-token'),
        () => v._login_vault('jwt', {jwt: 'secret-jwt'}),
      ]) {
        await assert.rejects(call(), err => {
          assert.match(err.message, /Unknown vault/);
          assert.ok(!/inherited-token|explicit-token|secret-jwt/.test(err.message));
          return true;
        });
      }
    })().catch(err => { console.error(err.message); process.exitCode = 1; });
  `;
  const result = await exec(process.execPath, ['-e', code], {
    cwd : project,
    env : {...process.env, HOME : home, VAUTHRC : '', VAULT_ADDR : '', VAULT_TOKEN : 'inherited-token'},
  });
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'Vauth token: inherited\n');
  assert.deepEqual(requests, []);
});


test('RC is the complete parsed JSON snapshot, frozen once and not reloaded by getters', t => {
  const document = {jwt_auth : {jwt : 'fixture-jwt', role : '$${env.ROLE}'}, env : {map : {NAME : '$${profile.NAME}'}}, extra : [{nested : true}]};
  const v = configuredClient(t, document, {ROLE : 'fixture-role', VAULT_ADDR : 'https://vault.example.test'});
  assert.deepEqual(v.RC, document);
  assert.equal(v.RC, v.RC);
  assert.equal(v.RC.vault_addr, undefined);
  assert.equal(v.VAULT_ADDR, 'https://vault.example.test');
  assert.ok(Object.isFrozen(v.RC));
  assert.ok(Object.isFrozen(v.RC.env.map));
  assert.ok(Object.isFrozen(v.RC.extra[0]));
  assert.throws(() => { v.RC.env.map.NAME = 'changed'; }, TypeError);
  assert.throws(() => { v.RC = {}; }, TypeError);
  document.env.map.NAME = 'caller-change';
  assert.equal(v.RC.env.map.NAME, '$${profile.NAME}');
  for(const name of ['rc', 'rc_file', 'RCFile']) assert.equal(v[name], undefined);
});

test('getters expose live token state while authentication expands only its private RC view', async t => {
  const f = await fixture(t);
  const v = f.client({rc : {jwt_auth : {jwt : 'fixture-jwt', role : '$${env.ROLE}'}, env : {map : {WHO : '$${profile.WHO}'}}}, env : {ROLE : 'actual-role'}});
  assert.equal(v.VAULT_TOKEN, '');
  assert.equal(v.RC.jwt_auth.role, '$${env.ROLE}');
  assert.equal(await v.Connect(), 'fresh-token');
  assert.equal(v.VAULT_TOKEN, 'fresh-token');
  assert.equal(JSON.parse(f.requests[0].body).role, 'actual-role');
  assert.equal(v.RC.env.map.WHO, '$${profile.WHO}');
  assert.throws(() => { v.VAULT_TOKEN = 'different'; }, TypeError);
});

test('subclasses can add their own state without freezing or sealing the client instance', t => {
  const v = configuredClient(t, {env : {map : {KEY : 'value'}}}, {}, Client => {
    class Consumer extends Client {
      constructor() { super(); this.config = structuredClone(this.RC.env); }
    }
    return new Consumer();
  });
  v.config.map.KEY = 'consumer-value';
  assert.equal(v.RC.env.map.KEY, 'value');
  assert.equal(v.config.map.KEY, 'consumer-value');
});
