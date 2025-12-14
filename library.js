const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const User = require.main.require('./src/user');
const db = require.main.require('./src/database');

const FlowPromptSSO = {};

/* ---------------- JWKS ---------------- */

const jwks = jwksClient({
  jwksUri: 'https://api.flowprompt.ai/.well-known/jwks.json',
  cache: true,
  rateLimit: true,
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }

    callback(null, key.getPublicKey());
  });
}

/* ---------------- INIT ---------------- */

FlowPromptSSO.init = async function ({ app, middleware }) {
  console.log('[FlowPrompt SSO] Plugin initialized');

  // KEEP ROUTE EXACTLY THE SAME
  app.get('/sso/jwt', middleware.buildHeader, FlowPromptSSO.handleJWT);
  app.get(
    '/sso/session-debug',
    middleware.buildHeader,
    FlowPromptSSO.debugSession,
  );

  console.log(
    '[FlowPrompt SSO] Routes registered: /sso/jwt, /sso/session-debug',
  );
};

/* ---------------- JWT HANDLER ---------------- */

FlowPromptSSO.handleJWT = async function (req, res) {
  try {
    const { token } = req.query;
    const redirect = req.query.redirect || '/';

    if (!token) {
      return res.status(400).send('Missing token');
    }

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(
        token,
        getKey,
        {
          audience: 'nodebb',
          issuer: 'flowprompt',
        },
        (err, decoded) => (err ? reject(err) : resolve(decoded)),
      );
    });

    const { uid: externalId, email, username, name, picture } = decoded;

    if (!externalId) {
      return res.status(400).send('Invalid token');
    }

    // Map external user → NodeBB uid
    let uid = await db.getObjectField('flowprompt:uid', externalId);

    if (!uid) {
      uid = await User.create({
        username: username || name || `fp_${externalId}`,
        email: email || undefined,
        fullname: name || '',
        picture: picture || null,
      });

      await db.setObjectField('flowprompt:uid', externalId, uid);

      if (email) {
        await User.setUserField(uid, 'email', email);
        await User.setUserField(uid, 'email:confirmed', 1);
      }

      console.log('[FlowPrompt SSO] Created user:', uid);
    }

    // Log the user into NodeBB
    req.session.uid = uid;

    // Optional helper cookie (safe)
    res.cookie('uid', uid, {
      domain: '.flowprompt.ai',
      path: '/',
      secure: true,
      sameSite: 'None',
    });

    console.log('[FlowPrompt SSO] Logged in UID:', uid);
    return res.redirect(redirect);
  } catch (err) {
    console.error('[FlowPrompt SSO] JWT error:', err.message);
    return res.status(400).send(err.message);
  }
};

/* ---------------- DEBUG ---------------- */

FlowPromptSSO.debugSession = async function (req, res) {
  const uid = req.session?.uid || null;

  const user = uid
    ? await User.getUserFields(uid, [
        'uid',
        'username',
        'email',
        'email:confirmed',
      ])
    : null;

  res.json({
    sessionUid: uid,
    user,
    cookies: req.cookies,
  });
};

module.exports = FlowPromptSSO;
