const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const User = require.main.require('./src/user');
const db = require.main.require('./src/database');

const client = jwksClient({
  jwksUri: 'https://api.flowprompt.ai/.well-known/jwks.json',
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }

    callback(null, key.getPublicKey());
  });
}

const FlowPromptSSO = {};

FlowPromptSSO.init = async function () {
  console.log('[FlowPrompt SSO] Plugin initialized');
};

FlowPromptSSO.addRoutes = async function ({ router, middleware }) {
  router.get('/sso/jwt', middleware.buildHeader, FlowPromptSSO.handleJWT);
  router.get(
    '/sso/session-debug',
    middleware.buildHeader,
    FlowPromptSSO.debugSession,
  );
};

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
      return res.status(400).send('Invalid token payload');
    }

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
    }

    // ✅ This is ALL that is needed
    req.session.uid = uid;

    res.cookie('uid', uid, {
      domain: '.flowprompt.ai',
      path: '/',
      secure: true,
      sameSite: 'None',
    });

    console.log('[FlowPrompt SSO] Login successful for UID:', uid);

    return res.redirect(redirect);
  } catch (err) {
    console.error('[FlowPrompt SSO] JWT error:', err.message);
    return res.status(400).send(err.message);
  }
};

FlowPromptSSO.debugSession = async function (req, res) {
  const uid = req.session?.uid;

  let user = null;

  if (uid) {
    user = await User.getUserFields(uid, [
      'uid',
      'username',
      'email',
      'email:confirmed',
      'fullname',
    ]);
  }

  res.json({
    sessionUid: uid || null,
    reqUser: user,
    cookies: req.cookies,
  });
};

module.exports = FlowPromptSSO;
