// library.js - FlowPrompt SSO plugin (updated)
// Fixes: robust nonce TTL, explicit cookie attribute overwrite (SameSite=None), uid cookie set, session cookie overwrite
'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');
const jwksClient = require('jwks-rsa');

const Plugin = {
  id: 'flowprompt-sso',
  name: 'FlowPrompt SSO',
  description: 'JWT-based SSO integration with FlowPrompt',
  version: '1.0.1',

  config: {
    flowpromptUrl: 'https://api.flowprompt.ai',
    publicKeyUrl: null,
    jwksUrl: null,
    publicKey: null,
    issuer: 'flowprompt',
    audience: 'nodebb',
    nonceStore: 'memory',
    redisUrl: 'redis://localhost:6379',
    autoCreateUsers: true,
    defaultGroup: 'registered-users',
    allowedRedirectHosts: '',
  },

  nonceStore: null,
  jwksClient: null,

  async init(params) {
    const { router, middleware } = params;
    const self = Plugin;

    // Load config from NodeBB meta/settings
    self.loadConfig();

    // Init nonce store safely
    self.initNonceStore();

    // Init JWKS if configured
    if (self.config.jwksUrl && !self.config.publicKey) {
      self.initJWKS();
    }

    // Register route
    router.get('/sso/jwt', middleware.maintenanceMode, self.handleSSO);

    // Middleware to populate req.user from session where missing
    const SSO_PROCESSED = Symbol('flowpromptSSOProcessed');
    router.use(async (req, res, next) => {
      if (req[SSO_PROCESSED] || req.user) return next();

      if (
        req.path.startsWith('/api/') ||
        req.path.startsWith('/assets/') ||
        req.path.startsWith('/uploads/') ||
        req.path.startsWith('/socket.io/')
      ) {
        return next();
      }

      if (req.session?.uid && !req.user) {
        req[SSO_PROCESSED] = true;
        const User = require.main.require('./src/user');
        try {
          const userData = await User.getUserFields(req.session.uid, [
            'uid',
            'username',
            'email',
            'picture',
            'joindate',
            'lastonline',
            'status',
          ]);
          if (userData) {
            req.user = userData;
            req.uid = req.session.uid;
            if (!global._flowpromptSSOLoggedSessions) {
              global._flowpromptSSOLoggedSessions = new Set();
            }
            if (!global._flowpromptSSOLoggedSessions.has(req.sessionID)) {
              global._flowpromptSSOLoggedSessions.add(req.sessionID);
              if (global._flowpromptSSOLoggedSessions.size > 100) {
                global._flowpromptSSOLoggedSessions.clear();
              }
              console.log(
                `[FlowPrompt SSO] Middleware: Loaded user ${req.session.uid} from session`,
              );
            }
          }
        } catch (err) {
          console.error(
            '[FlowPrompt SSO] Middleware: Error loading user:',
            err,
          );
        }
      }

      next();
    });

    // Debug route
    router.get('/sso/session-debug', async (req, res) => {
      if (req.session?.uid && !req.user) {
        const User = require.main.require('./src/user');
        try {
          const userData = await User.getUserFields(req.session.uid, [
            'uid',
            'username',
            'email',
          ]);
          if (userData) {
            req.user = userData;
            req.uid = req.session.uid;
            console.log(
              `[FlowPrompt SSO] Debug: Manually loaded user ${req.session.uid}`,
            );
          }
        } catch (err) {
          console.error('[FlowPrompt SSO] Debug: Error loading user:', err);
        }
      }

      return res.json({
        sessionId: req.sessionID,
        sessionUid: req.session?.uid || null,
        reqUid: req.uid || null,
        reqUser: req.user || null,
        cookies: req.cookies,
        manuallyLoaded: req.user ? 'yes' : 'no',
      });
    });

    // Admin routes
    router.get(
      '/admin/plugins/flowprompt-sso',
      middleware.admin.buildHeader,
      self.renderAdmin,
    );
    router.get('/api/admin/plugins/flowprompt-sso', self.renderAdmin);

    router.post(
      '/api/admin/plugins/flowprompt-sso',
      middleware.admin.checkPrivileges,
      self.saveSettings,
    );

    console.log('[FlowPrompt SSO] Plugin initialized');
    console.log(
      `[FlowPrompt SSO] FlowPrompt URL: ${self.config.flowpromptUrl}`,
    );
    console.log(
      `[FlowPrompt SSO] JWKS URL: ${self.config.jwksUrl || 'Not configured'}`,
    );
    console.log(
      `[FlowPrompt SSO] Public Key: ${self.config.publicKey ? 'Configured' : 'Not configured'}`,
    );

    return self;
  },

  loadConfig() {
    const self = Plugin;
    const meta = require.main.require('./src/meta');
    const settings = meta.settings.get('flowprompt-sso') || {};
    self.config = { ...self.config, ...settings };

    if (self.config.flowpromptUrl && !self.config.publicKeyUrl) {
      self.config.publicKeyUrl = `${self.config.flowpromptUrl}/api/sso/public-key.pem`;
    }
    if (self.config.flowpromptUrl && !self.config.jwksUrl) {
      self.config.jwksUrl = `${self.config.flowpromptUrl}/.well-known/jwks.json`;
    }
  },

  initNonceStore() {
    const self = Plugin;
    const db = require.main.require('./src/database');

    if (self.config.nonceStore === 'redis') {
      self.nonceStore = {
        async setNonce(nonce, ttl) {
          const key = `sso:nonce:${nonce}`;
          await db.setObject(key, { used: false, timestamp: Date.now() });
          await db.expire(key, ttl);
        },
        async consumeNonce(nonce) {
          const key = `sso:nonce:${nonce}`;
          const exists = await db.exists(key);
          if (exists) {
            await db.delete(key);
            return true;
          }
          return false;
        },
        async hasNonce(nonce) {
          const key = `sso:nonce:${nonce}`;
          return await db.exists(key);
        },
      };
    } else {
      const store = new Map();

      async function setNonceSafe(nonce, ttlSeconds) {
        let ttl = parseInt(ttlSeconds, 10);
        if (!Number.isFinite(ttl) || ttl <= 0) {
          ttl = 120;
        }
        store.set(nonce, Date.now());
        const ms = Math.max(1, ttl * 1000);
        setTimeout(() => {
          try {
            store.delete(nonce);
          } catch (e) {
            // ignore
          }
        }, ms);
      }

      self.nonceStore = {
        async setNonce(nonce, ttl) {
          await setNonceSafe(nonce, ttl);
        },
        async consumeNonce(nonce) {
          const exists = store.has(nonce);
          if (exists) {
            store.delete(nonce);
          }
          return exists;
        },
        async hasNonce(nonce) {
          return store.has(nonce);
        },
      };
    }
  },

  initJWKS() {
    const self = Plugin;
    self.jwksClient = jwksClient({
      jwksUri: self.config.jwksUrl,
      cache: true,
      cacheMaxAge: 3600000,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
    });
  },

  async getPublicKey(kid) {
    const self = Plugin;

    if (self.config.publicKey) {
      return self.config.publicKey;
    }

    if (self.jwksClient) {
      try {
        const key = await self.jwksClient.getSigningKey(kid);
        return key.getPublicKey();
      } catch (err) {
        console.error('[FlowPrompt SSO] Error fetching JWKS key:', err);
        throw new Error('Failed to fetch public key from JWKS');
      }
    }

    if (self.config.publicKeyUrl) {
      try {
        const response = await fetch(self.config.publicKeyUrl);
        if (!response.ok) {
          throw new Error(`Failed to fetch public key: ${response.statusText}`);
        }
        const publicKey = await response.text();
        return publicKey;
      } catch (err) {
        console.error('[FlowPrompt SSO] Error fetching public key:', err);
        throw new Error('Failed to fetch public key');
      }
    }

    throw new Error('No public key configuration found');
  },

  async verifyToken(token) {
    const self = Plugin;

    try {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || !decoded.header) {
        throw new Error('Invalid token format');
      }
      const { kid } = decoded.header;
      const publicKey = await self.getPublicKey(kid);
      const payload = jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
        issuer: self.config.issuer,
        audience: self.config.audience,
      });

      const nonce = payload.jti || payload.nonce;
      if (!nonce) {
        throw new Error('Token missing nonce (jti)');
      }

      const wasUsed = await self.nonceStore.hasNonce(nonce);
      if (wasUsed) {
        throw new Error('Token already used (replay attack detected)');
      }

      await self.nonceStore.consumeNonce(nonce);
      return payload;
    } catch (err) {
      console.error('[FlowPrompt SSO] Token verification error:', err.message);
      throw err;
    }
  },

  async findOrCreateUser(payload) {
    const self = Plugin;
    const User = require.main.require('./src/user');
    const Groups = require.main.require('./src/groups');

    const { email } = payload;
    if (!email) throw new Error('Token missing email claim');

    let uid = await User.getUidByEmail(email);
    if (uid) {
      const updateData = {};
      if (
        payload.name &&
        payload.name !== (await User.getUserField(uid, 'username'))
      ) {
        updateData.fullname = payload.name;
      }
      if (payload.picture) updateData.picture = payload.picture;
      if (Object.keys(updateData).length > 0) {
        await User.setUserFields(uid, updateData);
      }
      return uid;
    }

    if (!self.config.autoCreateUsers) {
      throw new Error('User not found and auto-create is disabled');
    }

    const username = payload.username || payload.name || email.split('@')[0];
    const fullname = payload.name || username;

    uid = await User.create({
      username,
      email,
      fullname,
      picture: payload.picture || '',
      'email:confirmed': 1,
      'email:validationPending': 0,
      'email:pending': 0,
    });

    try {
      await User.setUserField(uid, 'email', email);
      const UserEmail = require.main.require('./src/user/email');
      await UserEmail.confirmByUid(uid);
      console.log(
        `[FlowPrompt SSO] Email ${email} set and confirmed for user ${uid}`,
      );
    } catch (err) {
      console.error('[FlowPrompt SSO] Error setting email:', err);
    }

    if (self.config.defaultGroup) {
      try {
        await Groups.join(self.config.defaultGroup, uid);
      } catch (err) {
        console.error(
          '[FlowPrompt SSO] Error adding user to default group:',
          err,
        );
      }
    }

    console.log(`[FlowPrompt SSO] Created new user: ${username} (${email})`);
    return uid;
  },

  async createSession(req, res, uid) {
    const self = Plugin;
    const User = require.main.require('./src/user');
    const db = require.main.require('./src/database');

    if (req.session.uid) {
      console.log(
        `[FlowPrompt SSO] Clearing existing session for UID: ${req.session.uid}`,
      );
      if (req.session.uid === uid) {
        console.log(
          `[FlowPrompt SSO] User ${uid} already logged in, reusing existing session`,
        );
        req.session.jwt = true;
      } else {
        await new Promise((resolve, reject) => {
          if (!req.session || typeof req.session.regenerate !== 'function') {
            console.error(
              '[FlowPrompt SSO] Session regenerate method not available',
            );
            reject(new Error('Session regenerate method not available'));
            return;
          }
          req.session.regenerate((err) => {
            if (err) {
              console.error('[FlowPrompt SSO] Session regenerate error:', err);
              reject(err);
            } else {
              console.log(
                `[FlowPrompt SSO] Session regenerated with new ID: ${req.sessionID}`,
              );
              resolve();
            }
          });
        });
      }
    } else {
      console.log('[FlowPrompt SSO] No existing session, creating new one');
    }

    req.session.uid = uid;
    req.session.jwt = true;

    try {
      const userData = await User.getUserFields(uid, [
        'uid',
        'username',
        'email',
        'picture',
      ]);
      if (userData) {
        req.user = userData;
        req.uid = uid;
      }
    } catch (err) {
      console.error('[FlowPrompt SSO] Error loading user data:', err);
    }

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('[FlowPrompt SSO] Session save error:', err);
          reject(err);
        } else {
          console.log(
            `[FlowPrompt SSO] Session saved successfully with UID: ${uid}`,
          );
          resolve();
        }
      });
    });

    await User.updateLastOnlineTime(uid);
    await db.sortedSetAdd('users:online', Date.now(), uid);

    // Logging for debug
    console.log(`[FlowPrompt SSO] Created session for user: ${uid}`);
    console.log(`[FlowPrompt SSO] Session ID: ${req.sessionID}`);
    console.log(
      `[FlowPrompt SSO] Session UID in req.session: ${req.session.uid}`,
    );
  },

  async handleSSO(req, res, next) {
    const self = Plugin;

    try {
      const { token } = req.query;
      if (!token) {
        return res
          .status(400)
          .render('500', { error: 'Missing token parameter' });
      }

      const payload = await self.verifyToken(token);
      const uid = await self.findOrCreateUser(payload);
      await self.createSession(req, res, uid);

      // load user data into req.user to ensure middleware compatibility
      const User = require.main.require('./src/user');
      try {
        const userData = await User.getUserFields(uid, [
          'uid',
          'username',
          'email',
          'picture',
          'joindate',
          'lastonline',
          'status',
        ]);
        if (userData) {
          req.user = userData;
          req.uid = uid;
          console.log(
            `[FlowPrompt SSO] Loaded user data into req.user: ${userData.username}`,
          );
        }
      } catch (err) {
        console.error(
          '[FlowPrompt SSO] Error loading user data after session creation:',
          err,
        );
      }

      const redirectPath = payload.redirect || req.query.redirect || '/';
      const allowedHosts = (self.config.allowedRedirectHosts || '')
        .split(',')
        .filter(Boolean);

      if (allowedHosts.length > 0 && !redirectPath.startsWith('/')) {
        try {
          const redirectUrl = new URL(redirectPath, `https://${req.hostname}`);
          if (!allowedHosts.includes(redirectUrl.hostname)) {
            throw new Error('Redirect host not allowed');
          }
        } catch (err) {
          if (!redirectPath.startsWith('/')) {
            return res
              .status(400)
              .render('500', { error: 'Invalid redirect path' });
          }
        }
      }

      console.log(`[FlowPrompt SSO] Redirecting to: ${redirectPath}`);
      console.log(
        `[FlowPrompt SSO] Final check - Session UID: ${req.session.uid}`,
      );
      console.log(
        `[FlowPrompt SSO] Final check - Session ID: ${req.sessionID}`,
      );
      console.log(
        `[FlowPrompt SSO] Final check - req.user: ${req.user ? req.user.uid : 'undefined'}`,
      );

      // intercept express-session cookie creation and ensure SameSite=None is used
      const cookieName =
        (req.session && req.session.cookie && req.session.cookie.name) ||
        'express.sid';
      const originalCookie = res.cookie.bind(res);
      res.cookie = function (name, value, options) {
        if (name === cookieName) {
          const cookieDomain = (function () {
            try {
              const meta = require.main.require('./src/meta');
              return (
                (meta && meta.config && meta.config.cookieDomain) ||
                require('/srv/nodebb/config.json').cookieDomain ||
                '.flowprompt.ai'
              );
            } catch (e) {
              return '.flowprompt.ai';
            }
          })();

          const isSecure =
            req.protocol === 'https' ||
            (req.get && req.get('X-Forwarded-Proto') === 'https') ||
            !!req.secure;

          options = {
            ...options,
            domain: cookieDomain,
            sameSite: 'None',
            secure: !!isSecure,
            httpOnly: options?.httpOnly !== false,
            path: options?.path || '/',
          };
          console.log(
            '[FlowPrompt SSO] Intercepted',
            cookieName,
            'and set SameSite=None, Secure',
          );
        }
        return originalCookie(name, value, options);
      };

      // final save to ensure cookie is created
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) {
            console.error('[FlowPrompt SSO] Final session save error:', err);
            reject(err);
          } else {
            console.log('[FlowPrompt SSO] Final session save successful');
            resolve();
          }
        });
      });

      // robust cookieDomain detection
      let cookieDomain = null;
      try {
        const meta = require.main.require('./src/meta');
        if (meta && meta.config && meta.config.cookieDomain)
          cookieDomain = meta.config.cookieDomain;
      } catch (e) {}
      if (!cookieDomain) {
        try {
          const config = require('/srv/nodebb/config.json');
          if (config && config.cookieDomain) cookieDomain = config.cookieDomain;
        } catch (e) {}
      }
      if (!cookieDomain) cookieDomain = '.flowprompt.ai';

      const isSecure =
        req.protocol === 'https' ||
        (req.get && req.get('X-Forwarded-Proto') === 'https') ||
        !!req.secure;
      const baseOpts = {
        path: '/',
        domain: cookieDomain,
        sameSite: 'None',
        secure: !!isSecure,
      };

      // set uid cookie
      try {
        res.cookie('uid', String(uid), { ...baseOpts, httpOnly: false });
        console.log(
          `[FlowPrompt SSO] Set cookie uid=${uid} for domain ${cookieDomain}`,
        );
      } catch (e) {
        console.error(
          '[FlowPrompt SSO] Failed to set uid cookie',
          e && e.message,
        );
      }

      // At this point express-session likely set the signed session cookie in res.headers
      // To ensure SameSite/Domain attributes are correct we will inspect any Set-Cookie headers
      // and re-emit a cookie with the same value but with our desired flags.
      try {
        let existingSetCookies = res.getHeader && res.getHeader('Set-Cookie');
        if (!existingSetCookies) existingSetCookies = [];
        if (!Array.isArray(existingSetCookies))
          existingSetCookies = [existingSetCookies];

        // find cookie header for cookieName (express.sid)
        let found = null;
        for (const hdr of existingSetCookies) {
          if (typeof hdr === 'string' && hdr.startsWith(`${cookieName}=`)) {
            // extract the raw cookie value (before first ;)
            const firstPart = hdr.split(';')[0];
            const cookieValue = firstPart.substring(firstPart.indexOf('=') + 1);
            found = cookieValue;
            break;
          }
        }

        if (found) {
          // build new Set-Cookie header with SameSite=None and Domain
          const newCookie = `${cookieName}=${found}; Domain=${cookieDomain}; Path=/; HttpOnly; Secure; SameSite=None`;
          // append the new cookie header so browser receives it (alongside the original)
          const newSetCookies = existingSetCookies.concat([newCookie]);
          res.setHeader('Set-Cookie', newSetCookies);
          console.log(
            '[FlowPrompt SSO] Overwrote session cookie attributes via Set-Cookie header',
          );
        } else {
          // fallback: try to explicitly set cookie by name using req.sessionID as best-effort
          try {
            const cookieValAttempt = String(req.sessionID);
            res.cookie(cookieName, cookieValAttempt, {
              domain: cookieDomain,
              path: '/',
              httpOnly: true,
              secure: !!isSecure,
              sameSite: 'None',
            });
            console.log(
              '[FlowPrompt SSO] Fallback: set session cookie name with raw sessionID (may be unsigned)',
            );
          } catch (e) {
            console.warn(
              '[FlowPrompt SSO] Could not overwrite session cookie; proceeding anyway',
            );
          }
        }
      } catch (e) {
        console.error(
          '[FlowPrompt SSO] Error while trying to overwrite session cookie attributes:',
          e && e.message,
        );
      }

      // small delay to avoid race with client redirect + session store propagation
      await new Promise((r) => setTimeout(r, 100));

      // response caching headers
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      console.log(
        '[FlowPrompt SSO] Sending HTTP redirect with session cookie...',
      );
      return res.redirect(302, redirectPath);
    } catch (err) {
      console.error('[FlowPrompt SSO] SSO error:', err);
      return res.status(401).render('500', {
        error: 'SSO authentication failed',
        message: err.message,
      });
    }
  },

  async renderAdmin(req, res, next) {
    const self = Plugin;
    res.render('admin/plugins/flowprompt-sso', {
      title: 'FlowPrompt SSO Settings',
      config: self.config,
    });
  },

  async saveSettings(req, res, next) {
    const self = Plugin;
    const meta = require.main.require('./src/meta');

    const settings = {
      flowpromptUrl: req.body.flowpromptUrl || '',
      publicKey: req.body.publicKey || '',
      issuer: req.body.issuer || 'flowprompt',
      audience: req.body.audience || 'nodebb',
      nonceStore: req.body.nonceStore || 'memory',
      redisUrl: req.body.redisUrl || 'redis://localhost:6379',
      autoCreateUsers: req.body.autoCreateUsers === 'on',
      defaultGroup: req.body.defaultGroup || 'registered-users',
      allowedRedirectHosts: req.body.allowedRedirectHosts || '',
    };

    await meta.settings.set('flowprompt-sso', settings);
    self.config = { ...self.config, ...settings };

    if (settings.nonceStore !== self.config.nonceStore) {
      self.initNonceStore();
    }
    if (settings.flowpromptUrl && !settings.publicKey) {
      self.initJWKS();
    }

    res.json({ status: 'ok' });
  },
};

module.exports = Plugin;
