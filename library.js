const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const User = require.main.require('./src/user');
const Meta = require.main.require('./src/meta');
const db = require.main.require('./src/database');

const plugin = {};

let jwks = null;

async function getUidByEmailSafe(email) {
  email = email.toLowerCase().trim();
  console.log('[FlowPrompt SSO] Getting UID by email:', email);

  let uid = await User.getUidByEmail(email);

  console.log('[FlowPrompt SSO] UID (official):', uid);

  if (!uid) {
    uid = await db.getObjectField('email:uid', email);
    console.log('[FlowPrompt SSO] UID (email:uid):', uid);
  }

  return uid ? parseInt(uid, 10) : null;
}

/**
 * INIT
 */
plugin.init = async function ({ router, middleware }) {
  console.log('[FlowPrompt SSO] Plugin initialized');

  const FLOWPROMPT_LOGIN = 'https://flowprompt.ai/?forum=true';

  const settings = await Meta.settings.get('flowprompt-sso');

  const apiUrl = settings.apiUrl || 'https://api.flowprompt.ai';
  const issuer = settings.issuer || 'flowprompt';
  const audience = settings.audience || 'nodebb';

  console.log('[FlowPrompt SSO] FlowPrompt URL:', apiUrl);

  router.get('/login', async (req, res) => {
    console.log('[FlowPrompt SSO] Login requested');
    console.log('[FlowPrompt SSO] UID:', req.uid);
    console.log('[FlowPrompt SSO] User:', req.user);

    if (req.uid && req.user?.isAdmin) {
      // Admin allowed to see local login
      return res.render('login');
    }

    console.log(
      '[FlowPrompt SSO] Redirecting to:',
      `${FLOWPROMPT_LOGIN}&mode=login`,
    );

    return res.redirect(`${FLOWPROMPT_LOGIN}&mode=login`);
  });

  router.post('/login', async (req, res) => {
    console.log('[FlowPrompt SSO] Login POST requested');
    console.log('[FlowPrompt SSO] UID:', req.uid);
    console.log('[FlowPrompt SSO] User:', req.user);

    // Allow admin password login ONLY
    if (req.uid && req.user?.isAdmin) {
      return res.redirect('/'); // let NodeBB handle admin session
    }

    const externalUrl = `${FLOWPROMPT_LOGIN}&mode=login`;

    // 2. Check if the request is AJAX (XHR)
    if (
      req.xhr ||
      (req.headers.accept && req.headers.accept.indexOf('json') > -1)
    ) {
      console.log(
        '[FlowPrompt SSO] AJAX request detected, sending external redirect signal',
      );

      // This is the key: NodeBB client-side looks for the 'external' property
      // in a 200 OK response to break out of the AJAX flow.
      return res.status(401).json({
        redirect: externalUrl,
      });
    }

    // 3. Fallback for non-AJAX direct hits
    console.log('[FlowPrompt SSO] Direct hit, redirecting normally');
    return res.redirect(externalUrl);
  });

  router.get('/register', (req, res) => {
    console.log('[FlowPrompt SSO] Register requested');
    console.log('[FlowPrompt SSO] UID:', req.uid);
    console.log('[FlowPrompt SSO] User:', req.user);

    console.log(
      '[FlowPrompt SSO] Register Redirecting to:',
      `${FLOWPROMPT_LOGIN}&mode=register`,
    );
    return res.redirect(`${FLOWPROMPT_LOGIN}&mode=register`);
  });

  router.post('/register', (req, res) => {
    console.log('[FlowPrompt SSO] Register POST requested');
    console.log('[FlowPrompt SSO] UID:', req.uid);
    console.log('[FlowPrompt SSO] User:', req.user);

    return res.redirect(`${FLOWPROMPT_LOGIN}&mode=register`);
  });

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

      console.log('[FlowPrompt SSO] Payload Email:', payload.email);

      if (!payload.email) {
        return res.status(400).send('Email missing in token');
      }

      // Nonce protection
      const nonceKey = `flowprompt:nonce:${payload.nonce}`;
      const used = await db.get(nonceKey);

      if (used) {
        console.log('[FlowPrompt SSO] Nonce already used');
        return res.redirect('https://community.flowprompt.ai');
        // return res.status(400).send('Nonce already used');
      }

      await db.set(nonceKey, '1');
      await db.expire(nonceKey, 120);

      // Find or create user
      let uid = await getUidByEmailSafe(payload.email);

      console.log('[FlowPrompt SSO] User ID:', uid);

      if (!uid) {
        uid = await User.create({
          username:
            payload.username || payload.email.split('@')[0] || payload.name,
          email: payload.email,
        });

        console.log('[FlowPrompt SSO] User created:', uid);
      }

      if (payload.email) {
        await User.setUserField(uid, 'email', payload.email);
        await User.setUserField(uid, 'email:confirmed', 1);
        await User.setUserField(uid, 'flowprompt:id', payload.userId);
        await db.setObjectField('email:uid', payload.email, uid);
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
plugin.addClientScript = async function (scripts) {
  console.log('[FlowPrompt SSO] filter:scripts.get called');

  scripts.push('/plugins/nodebb-plugin-flowprompt-sso/client.js');

  return scripts;
};

module.exports = plugin;
