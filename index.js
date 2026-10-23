#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const {createHash, randomUUID} = require('crypto');
const {encrypt, decrypt} = require('ssh-agent-crypt');
const promptBool = require('cnyks/prompt/bool');

const {parse} = require('yaml');
const semver     = require('semver');
const trim       = require('mout/string/trim');
const eachLimit = require('nyks/async/eachLimit');
const walk       = require('nyks/object/walk');
const humanDiff  = require('nyks/date/humanDiff');

const request    = require('nyks/http/request');
const drain      = require('nyks/stream/drain');
const replaceEnv = require('nyks/string/replaceEnv');
const promiser   = require('nyks/function/promiser');


const {createAgent} = require('ssh2/lib/agent');
const debug = require('debug');

const logger  = {
  debug : debug('vauth-login:debug'),
  info  : debug('vauth-login:info'),
  error : debug('vauth-login:error'),
};


const {name : PACKAGE_NAME, version : VERSION} = require('./package.json');
const HOME_RC  = path.join(os.homedir(), ".vauthrc");
const VAUTH_RC = [process.env.VAUTHRC, path.join(process.cwd(), ".vauthrc"), HOME_RC];
const RC_KEYS  = ['vault_addr', 'ssh_auth', 'jwt_auth', 'token_cache', 'known_vaults'];

const normalizeAddr = addr => trim(String(addr || ''), '/');

// Read the authentication keys of a .vauthrc, expanding $${env.X} macros.
function loadRC(file, env = process.env) {
  const rc = parse(fs.readFileSync(file, 'utf8'));
  return walk(Object.fromEntries(RC_KEYS.filter(key => rc && Object.hasOwn(rc, key)).map(key => [key, rc[key]])), v => replaceEnv(v, {env}));
}

class HTTPError extends Error {
  constructor(status, body) {
    super(`Unexpected Vault status ${status}`);
    this.status = status;
    // The response remains available to callers, while error logging shows status.
    Object.defineProperty(this, 'body', {value : body});
    this.res = {statusCode : status};
  }
}

class VauthLogin {
  constructor() {


    // A project may pin the vauth-login version it expects.
    // Only vauth-login itself is checked, against the running version.
    let manifest = path.resolve('package.json');
    if(fs.existsSync(manifest)) {
      const {dependencies = {}} = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      const required = dependencies[PACKAGE_NAME];
      if(required && !semver.satisfies(VERSION, required))
        throw `Unsupported ${PACKAGE_NAME} version ${VERSION} (project requires ${required})`;
    }

    this.rc = {};

    let vauth_rc = VAUTH_RC.filter(path => path && fs.existsSync(path))[0];
    if(vauth_rc)
      this.rc = loadRC(vauth_rc);
    this.rc_file = vauth_rc;

    if(!process.env.SSH_AUTH_SOCK && process.platform !== 'win32')
      this.rc.token_cache = false;

    this.VAULT_ADDR = this.rc.vault_addr || process.env.VAULT_ADDR; //might be null
    this.VAULT_TOKEN = process.env.VAULT_TOKEN;

    // A project's ./.vauthrc chooses the Vault; the user vouches for it in
    // ~/.vauthrc (its vault_addr or its known_vaults list), or is asked.
    this._unknown_vault = false;
    if(vauth_rc === VAUTH_RC[1] && vauth_rc !== HOME_RC && this.rc.vault_addr) {
      const home = fs.existsSync(HOME_RC) ? loadRC(HOME_RC) : {};
      const known = [home.vault_addr, ...(Array.isArray(home.known_vaults) ? home.known_vaults : [])].map(normalizeAddr);
      this._unknown_vault = !known.includes(normalizeAddr(this.rc.vault_addr));
    }


  }

  static version() {
    return VERSION;
  }

  version() {
    return VauthLogin.version();
  }

  // Ask once before the first request to a Vault chosen by ./.vauthrc that
  // ~/.vauthrc does not know. Without a terminal, refuse.
  async _trust_vault(accept = false) {
    if(!this._unknown_vault || accept)
      return;
    const where = `Unknown vault ${normalizeAddr(this.VAULT_ADDR)}, selected by ${this.rc_file}`;
    const hint = 'Add it to known_vaults in ~/.vauthrc to stop being asked.';
    if(!process.stdin.isTTY)
      throw new Error(`${where}. ${hint}`);
    if(!await promptBool(`${where}.\n${hint}\nContinue? `, false))
      throw new Error(`Unknown vault ${normalizeAddr(this.VAULT_ADDR)}: refused`);
    this._unknown_vault = false;
  }

  _token_cache_key() {
    const {ssh_auth, jwt_auth} = this.rc;
    return createHash('sha256').update(JSON.stringify({
      vault_addr : trim(this.VAULT_ADDR || '', '/'), ssh_auth, jwt_auth,
    })).digest('hex');
  }

  _token_cache_file() {
    return path.join(os.homedir(), '.vauth', 'tokens', this._token_cache_key() + '.creds');
  }

  async _read_token_cache() {
    if(this.rc.token_cache === false)
      return;
    try {
      const armor = fs.readFileSync(this._token_cache_file(), 'utf8');
      return JSON.parse(await decrypt(armor));
    } catch(err) {}
  }

  async _save_cached_token(token, metadata) {
    if(this.rc.token_cache === false)
      return;
    const ttl = metadata.ttl === undefined ? metadata.lease_duration : metadata.ttl;
    const file = this._token_cache_file();
    const temporary = file + '.' + randomUUID() + '.next';
    try {
      const {lease_duration} = metadata;
      const cache = {
        token, lease_duration, renewable : metadata.renewable === true,
        expires_at : ttl === 0 ? null : Date.now() + ttl * 1000,
      };
      fs.mkdirSync(path.dirname(file), {recursive : true, mode : 0o700});
      const identity = process.env.VAUTH_USER_IDENTITY || process.env.VAUTH_USER_MAIL;
      const armor = await encrypt(JSON.stringify(cache), identity);
      fs.writeFileSync(temporary, armor, {mode : 0o600, flag : 'wx'});
      fs.renameSync(temporary, file);
    } catch(err) {
      // Cache failures must not prevent authentication or expose credentials.
      console.error('Could not encrypt/write token cache; token not persisted');
    } finally {
      try { fs.unlinkSync(temporary); } catch(err) {}
    }
  }

  _token_status(operation, metadata) {
    const ttl = metadata.ttl === undefined ? metadata.lease_duration : metadata.ttl;
    const validity = ttl === 0 ? 'valid indefinitely' : humanDiff(ttl, 2);
    console.error('Vauth token: %s · %s', operation, validity);
  }

  async connect(renew = false, accept = false) /**
  * @interactive_runner hide
  */ {
    if(this._connected && !renew)
      return this.VAULT_TOKEN;

    // An inherited token is the caller's: returned as is, never looked up,
    // renewed or persisted.
    if(this.VAULT_TOKEN && !renew) {
      console.error('Vauth token: inherited');
      this._connected = true;
      return this.VAULT_TOKEN;
    }

    const {ssh_auth, jwt_auth} = this.rc;
    if(!ssh_auth && !jwt_auth) {
      this.VAULT_TOKEN = undefined;
      return;
    }
    this._connected = false;

    const cached = await this._read_token_cache();
    let token = cached && cached.token;
    const had_token = !!token;
    let metadata, operation = 'reused';
    if(renew || (cached && cached.expires_at !== null && cached.expires_at <= Date.now()))
      token = undefined;

    if(token) {
      const ttl = cached.expires_at === null ? 0 : (cached.expires_at - Date.now()) / 1000;
      metadata = {...cached, ttl};
      if(ttl > 0 && ttl <= cached.lease_duration / 3) {
        if(cached.renewable) {
          try {
            await this._trust_vault(accept);
            metadata = await this._renew_token(token);
            token = metadata.client_token;
            operation = 'renewed';
          } catch(err) {
            // Reauthenticate on invalid tokens, not network/server failures.
            const status = err.res && err.res.statusCode;
            if(![400, 403].includes(status))
              throw err;
            token = undefined;
          }
        } else {
          token = undefined;
        }
      }
    }

    if(!token) {
      await this._trust_vault(accept);
      const agent_path = process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? 'pageant' : null);
      if(ssh_auth && agent_path) {
        metadata = await this._login_vault_ssh({...ssh_auth}, agent_path);
      } else if(jwt_auth && jwt_auth.jwt) {
        const {path, jwt, role} = jwt_auth;
        metadata = await this._login_vault(path || 'jwt', {jwt, role});
      }
      token = metadata && metadata.client_token;
      if(!token && (renew || had_token))
        throw new Error('Could not login to vault: no authentication method available');
      operation = 'generated';
    }

    if(token) {
      if(operation !== 'reused')
        await this._save_cached_token(token, metadata);
      this._token_status(operation, metadata);
    }
    this.VAULT_TOKEN = token;
    this._connected = true;
    return token;
  }

  async _renew_token(token) {
    const {body} = await this.request('POST', 'auth/token/renew-self', token, {}, 200);
    const auth = JSON.parse(body).auth;
    if(!auth || !auth.client_token || !Number.isFinite(auth.lease_duration) || auth.lease_duration < 0)
      throw new Error('Invalid Vault token renewal response');
    return auth;
  }

  async login(renew = false, accept = false) /**
  * Authenticate and return the token
  * @alias connect
  */ {
    return this.connect(renew, accept);
  }

  async _login_vault_ssh({path = 'ssh', role}, agent_path = process.env.SSH_AUTH_SOCK) {
    logger.info("Trying to auth as '%s'", role);

    let agent = createAgent(agent_path);
    let keys = await promiser(chain => agent.getIdentities(chain));


    let auth;
    await eachLimit(keys, 1, async (pubKey) => {
      if(auth)
        return;

      const {body} = await this.request('GET', `auth/${path}/nonce`, '', null, 200);
      const {data : {nonce} = {}} = JSON.parse(body);
      if(typeof nonce !== 'string' || !nonce)
        throw new Error('Invalid Vault nonce response');

      const signature =  (await promiser(chain => agent.sign(pubKey, Buffer.from(nonce), {}, chain))).toString('base64');
      const public_key = pubKey.type + ' ' + pubKey.getPublicSSH().toString('base64');
      const payload = {public_key, role, nonce : Buffer.from(nonce).toString('base64'), signature};
      try {
        auth = await this._login_vault(path, payload);
      } catch(err) {
        logger.debug("ssh : invalid challenge for public key", pubKey.comment);
      }
    });


    if(!auth || !auth.client_token)
      throw `Could not login to vault`;

    return auth;
  }
  async _lookup_token(token) {
    const {body} = await this.request('GET', 'auth/token/lookup-self', token, null, 200);
    const response = JSON.parse(body).data;
    if(!response || !Number.isFinite(response.ttl) || response.ttl < 0)
      throw new Error('Invalid Vault token TTL');
    const cached = await this._read_token_cache();
    response.lease_duration = cached && cached.token === token ? cached.lease_duration : response.creation_ttl;
    return response;
  }

  async lookupSelf(token = this.VAULT_TOKEN) {
    return this._lookup_token(token);
  }

  async _login_vault(path, payload) {
    const {body} = await this.request('POST', `auth/${path}/login`, '', payload, 200);
    const auth = JSON.parse(body).auth;
    if(!auth || !auth.client_token || !Number.isFinite(auth.lease_duration) || auth.lease_duration < 0)
      throw new Error('Invalid Vault login response');
    return auth;
  }

  vaultURL(apiPath) {
    return `${trim(this.VAULT_ADDR || '', '/')}/v1/${String(apiPath).replace(/^\/+/, '')}`;
  }

  async request(method, apiPath, token = '', payload = null, expect = 200) {
    const headers = {};
    if(token) headers['X-Vault-Token'] = token;
    if(payload !== null) headers['Content-Type'] = 'application/json';
    const query = {...url.parse(this.vaultURL(apiPath)), method, headers, json : true,
      reqtimeout : this.requestTimeout || 60000};
    const res = await request(query, payload);
    const body = await drain(res);
    if(expect && res.statusCode !== expect)
      throw new HTTPError(res.statusCode, body.toString());
    return {status : res.statusCode, body};
  }

}

//ensure module is called directly, i.e. not required
if(module.parent === null) {
  const {args, dict} = require('nyks/process/parseArgs')();
  let cmd = args.shift() || 'login';
  if(dict.version) cmd = 'version';
  if(dict.help || cmd === 'help') cmd = '?';
  const flags = ['--ir://raw'];
  if(!dict['ir://run'] && !dict['ir://start']) flags.push(`--ir://run=${cmd}`);
  if(cmd === 'version' || dict['ir://run'] === 'version') flags.push('--ir://static');
  require('cnyks/lib/bundle')(VauthLogin, 'vauth-login', flags);
}

module.exports = VauthLogin;
module.exports.HTTPError = HTTPError;
