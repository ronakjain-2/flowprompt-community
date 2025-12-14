const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const crypto = require('crypto');

const User = require.main.require('./src/user');
const Meta = require.main.require('./src/meta');
const db = require.main.require('./src/database');
const nconf = require.main.require('nconf');

const plugin = {};

let jwks = null;

/**
 * INIT
 */
plugin.init = async function ({ router, middleware }) {
  console.log('[FlowPrompt SSO] Plugin initialized');

  const settings = await Meta.settings.get('flowprompt-sso');

  const apiUrl = settings.apiUrl || 'https://api.flowprompt.ai';
  const issuer = settings.issuer || 'flowprompt';
  const audience = settings.audience || 'nodebb';

  console.log('[FlowPrompt SSO] FlowPrompt URL:', apiUrl);

  jwks = jwksClient({
    jwksUri: `${apiUrl}/.well-known/jwks.json`,
    cache: true,
    rateLimit: true,
  });

  router.get('/sso/jwt', middleware.buildHeader, async (req, res) => {
    try {
      const { token } = req.query;

      if (!token) {
        return res.status(400).send('Missing token');
      }

      const decodedHeader = jwt.decode(token, { complete: true });

      if (!decodedHeader) {
        return res.status(400).send('Invalid token');
      }

      const key = await jwks.getSigningKey(decodedHeader.header.kid);
      const publicKey = key.getPublicKey();

      const payload = jwt.verify(token, publicKey, {
        issuer,
        audience,
      });

      if (!payload.email) {
        return res.status(400).send('Email missing in token');
      }

      // Nonce protection
      const nonceKey = `flowprompt:nonce:${payload.nonce}`;
      const used = await db.get(nonceKey);

      if (used) {
        return res.status(400).send('Nonce already used');
      }

      await db.set(nonceKey, '1');
      await db.expire(nonceKey, 120);

      // Find or create user
      let uid = await User.getUidByEmail(payload.email);

      if (!uid) {
        uid = await User.create({
          username: payload.name || payload.email.split('@')[0],
          email: payload.email,
        });
      }

      // 🔐 LOG USER IN (NodeBB native)
      await new Promise((resolve, reject) => {
        req.login({ uid }, (err) => (err ? reject(err) : resolve()));
      });

      // Force session save
      req.session.uid = uid;
      await new Promise((resolve) => req.session.save(resolve));

      // Set UID cookie for cross-subdomain access
      res.cookie('uid', uid, {
        domain: '.flowprompt.ai',
        secure: true,
        sameSite: 'None',
        path: '/',
      });

      console.log('[FlowPrompt SSO] User logged in:', uid);

      res.redirect('/');
    } catch (err) {
      console.error('[FlowPrompt SSO] Error:', err);
      res.status(401).send('SSO failed');
    }
  });
};

/**
 * HEADER INJECTION (MINIMAL – NO SOCKET HACKING)
 */
plugin.filterHeaderBuild = async function (data) {
  data.scripts = data.scripts || [];

  data.scripts.push({
    src: '/plugins/nodebb-plugin-flowprompt-sso/client.js',
    defer: true,
  });

  return data;
};

module.exports = plugin;
