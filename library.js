const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fetch = require('node-fetch');
const jwksClient = require('jwks-rsa');

const Plugin = {
  /**
   * Plugin metadata
   */
  id: 'flowprompt-sso',
  name: 'FlowPrompt SSO',
  description: 'JWT-based SSO integration with FlowPrompt',
  version: '1.0.0',

  /**
   * Plugin configuration (set via NodeBB Admin Panel)
   */
  config: {
    flowpromptUrl: 'https://api.flowprompt.ai',
    publicKeyUrl: null, // Auto-set from flowpromptUrl
    jwksUrl: null, // Auto-set from flowpromptUrl
    publicKey: null, // Direct PEM key (alternative to JWKS)
    issuer: 'flowprompt',
    audience: 'nodebb',
    nonceStore: 'memory', // 'memory' or 'redis'
    redisUrl: 'redis://localhost:6379',
    autoCreateUsers: true,
    defaultGroup: 'registered-users',
  },

  /**
   * Nonce store for one-time token validation
   */
  nonceStore: null,

  /**
   * JWKS client for key discovery
   */
  jwksClient: null,

  /**
   * Initialize plugin
   */
  async init(params) {
    const { router, middleware, controllers } = params;
    const self = Plugin;

    // Load configuration from NodeBB settings
    self.loadConfig();

    // Initialize nonce store
    self.initNonceStore();

    // Initialize JWKS client if using JWKS
    if (self.config.jwksUrl && !self.config.publicKey) {
      self.initJWKS();
    }

    // Register SSO route
    // Note: We skip CSRF for this GET redirect flow, but ensure session middleware runs
    // The session middleware should already be running globally, but we ensure it's active
    router.get('/sso/jwt', middleware.maintenanceMode, self.handleSSO);

    // Register admin settings page
    router.get(
      '/admin/plugins/flowprompt-sso',
      middleware.admin.buildHeader,
      self.renderAdmin,
    );
    router.get('/api/admin/plugins/flowprompt-sso', self.renderAdmin);

    // Register settings save endpoint
    router.post(
      '/api/admin/plugins/flowprompt-sso',
      middleware.admin.checkPrivileges,
      self.saveSettings,
    );

    // Log initialization
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

  /**
   * Load configuration from NodeBB settings
   */
  loadConfig() {
    const self = Plugin;
    const meta = require.main.require('./src/meta');

    // Load settings from database
    const settings = meta.settings.get('flowprompt-sso') || {};

    // Merge with defaults
    self.config = {
      ...self.config,
      ...settings,
    };

    // Auto-set URLs if flowpromptUrl is provided
    if (self.config.flowpromptUrl && !self.config.publicKeyUrl) {
      self.config.publicKeyUrl = `${self.config.flowpromptUrl}/api/sso/public-key.pem`;
    }

    if (self.config.flowpromptUrl && !self.config.jwksUrl) {
      self.config.jwksUrl = `${self.config.flowpromptUrl}/.well-known/jwks.json`;
    }
  },

  /**
   * Initialize nonce store
   */
  initNonceStore() {
    const self = Plugin;
    const db = require.main.require('./src/database');

    if (self.config.nonceStore === 'redis') {
      // Use NodeBB's Redis connection
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
      // In-memory store (for development)
      const store = new Map();

      self.nonceStore = {
        async setNonce(nonce, ttl) {
          store.set(nonce, Date.now());
          setTimeout(() => store.delete(nonce), ttl * 1000);
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

  /**
   * Initialize JWKS client
   */
  initJWKS() {
    const self = Plugin;

    self.jwksClient = jwksClient({
      jwksUri: self.config.jwksUrl,
      cache: true,
      cacheMaxAge: 3600000, // 1 hour
      rateLimit: true,
      jwksRequestsPerMinute: 5,
    });
  },

  /**
   * Get public key for JWT verification
   */
  async getPublicKey(kid) {
    const self = Plugin;

    // If direct public key is configured, use it
    if (self.config.publicKey) {
      return self.config.publicKey;
    }

    // If JWKS is configured, fetch key
    if (self.jwksClient) {
      try {
        const key = await self.jwksClient.getSigningKey(kid);

        return key.getPublicKey();
      } catch (err) {
        console.error('[FlowPrompt SSO] Error fetching JWKS key:', err);
        throw new Error('Failed to fetch public key from JWKS');
      }
    }

    // Fallback: fetch from public key URL
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

  /**
   * Verify JWT token
   */
  async verifyToken(token) {
    const self = Plugin;

    try {
      // Decode token header to get kid
      const decoded = jwt.decode(token, { complete: true });

      if (!decoded || !decoded.header) {
        throw new Error('Invalid token format');
      }

      const { kid } = decoded.header;

      // Get public key
      const publicKey = await self.getPublicKey(kid);

      // Verify token
      const payload = jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
        issuer: self.config.issuer,
        audience: self.config.audience,
      });

      // Check nonce (one-time use)
      const nonce = payload.jti || payload.nonce;

      if (!nonce) {
        throw new Error('Token missing nonce (jti)');
      }

      // Check if nonce was already used
      const wasUsed = await self.nonceStore.hasNonce(nonce);

      if (wasUsed) {
        throw new Error('Token already used (replay attack detected)');
      }

      // Consume nonce
      await self.nonceStore.consumeNonce(nonce);

      return payload;
    } catch (err) {
      console.error('[FlowPrompt SSO] Token verification error:', err.message);
      throw err;
    }
  },

  /**
   * Find or create NodeBB user
   */
  async findOrCreateUser(payload) {
    const self = Plugin;
    const User = require.main.require('./src/user');
    const Groups = require.main.require('./src/groups');

    const { email } = payload;

    if (!email) {
      throw new Error('Token missing email claim');
    }

    // Try to find existing user by email
    let uid = await User.getUidByEmail(email);

    if (uid) {
      // User exists - update profile if needed
      const updateData = {};

      if (
        payload.name &&
        payload.name !== (await User.getUserField(uid, 'username'))
      ) {
        // Note: Username changes might require admin privileges
        // For now, just update fullname
        updateData.fullname = payload.name;
      }

      if (payload.picture) {
        updateData.picture = payload.picture;
      }

      if (Object.keys(updateData).length > 0) {
        await User.setUserFields(uid, updateData);
      }

      return uid;
    }

    // User doesn't exist - create new user
    if (!self.config.autoCreateUsers) {
      throw new Error('User not found and auto-create is disabled');
    }

    const username = payload.username || payload.name || email.split('@')[0];
    const fullname = payload.name || username;

    // Create user
    uid = await User.create({
      username,
      email,
      fullname,
      picture: payload.picture || '',
      // Ensure NodeBB treats the email as confirmed to avoid validation email
      'email:confirmed': 1,
      'email:validationPending': 0,
      'email:pending': 0,
    });

    // Add to default group
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

  /**
   * Create NodeBB session
   */
  async createSession(req, res, uid) {
    const self = Plugin;
    const User = require.main.require('./src/user');
    const db = require.main.require('./src/database');
    const meta = require.main.require('./src/meta');

    // Clear any existing session data first
    if (req.session.uid) {
      console.log(
        `[FlowPrompt SSO] Clearing existing session for UID: ${req.session.uid}`,
      );
    }

    // CRITICAL: Regenerate session to prevent session fixation attacks
    // and ensure a fresh session ID is created
    // regenerate() automatically destroys the old session and creates a new one
    // We don't need to destroy manually - regenerate handles it
    await new Promise((resolve, reject) => {
      // Check if regenerate method exists (it should always exist in express-session)
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

    // Set user session - this is the key to authentication in NodeBB
    // NodeBB checks req.session.uid to determine if user is logged in
    req.session.uid = uid;
    req.session.jwt = true; // Mark as JWT-authenticated

    // Also set req.user for NodeBB middleware compatibility
    // Some NodeBB middleware checks req.user instead of req.session.uid
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
      // Continue anyway - req.session.uid should be enough
    }

    // CRITICAL: Save session and ensure it's committed to store
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

    // Update user last login time
    await User.updateLastOnlineTime(uid);

    // Mark user as online in NodeBB's sorted set
    await db.sortedSetAdd('users:online', Date.now(), uid);

    // Get NodeBB cookie configuration
    const cookieDomain = meta.config.cookieDomain || '';

    // Get cookie name from session store (express-session stores it here)
    const cookieName =
      req.sessionStore?.cookie?.name ||
      req.session?.cookie?.name ||
      'express.sid';

    // Determine secure flag from request
    const isSecure =
      req.protocol === 'https' ||
      req.get('X-Forwarded-Proto') === 'https' ||
      req.secure ||
      false;

    // Let express-session/NodeBB set the session cookie (signed) to avoid duplicates
    // Setting it manually can create a second, unsigned cookie. The NodeBB session
    // middleware will set the correct cookie (with signature) based on its config.

    // Verify session is set correctly
    console.log(`[FlowPrompt SSO] Created session for user: ${uid}`);
    console.log(`[FlowPrompt SSO] Session ID: ${req.sessionID}`);
    console.log(
      `[FlowPrompt SSO] Session UID in req.session: ${req.session.uid}`,
    );
    console.log(`[FlowPrompt SSO] Cookie name: ${cookieName}`);
    console.log(`[FlowPrompt SSO] Cookie secure: ${isSecure}`);
    console.log(
      `[FlowPrompt SSO] Cookie domain: ${cookieDomain || 'default (not set)'}`,
    );
    console.log(`[FlowPrompt SSO] Request protocol: ${req.protocol}`);
    console.log(
      `[FlowPrompt SSO] X-Forwarded-Proto: ${req.get('X-Forwarded-Proto') || 'not set'}`,
    );

    // Double-check: verify session was saved to store
    const sessionStore = req.sessionStore;
    if (sessionStore) {
      sessionStore.get(req.sessionID, (err, session) => {
        if (err) {
          console.error(
            '[FlowPrompt SSO] Error getting session from store:',
            err,
          );
        } else if (session && session.uid === uid) {
          console.log(
            '[FlowPrompt SSO] Session verified in store - UID matches',
          );
        } else {
          console.error(
            '[FlowPrompt SSO] Session NOT found in store or UID mismatch',
          );
        }
      });
    }
  },

  /**
   * Handle SSO request
   * GET /sso/jwt?token=<jwt>&redirect=<path>
   */
  async handleSSO(req, res, next) {
    const self = Plugin;

    try {
      // Get token from query parameter
      const { token } = req.query;

      if (!token) {
        return res.status(400).render('500', {
          error: 'Missing token parameter',
        });
      }

      // Verify token
      const payload = await self.verifyToken(token);

      // Find or create user
      const uid = await self.findOrCreateUser(payload);

      // Create session
      await self.createSession(req, res, uid);

      // CRITICAL: After creating session, ensure NodeBB's authentication middleware
      // recognizes the user. We need to explicitly load the user data into req.user
      // so that NodeBB's middleware chain recognizes the authenticated user.
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

      // Get redirect path
      const redirectPath = payload.redirect || req.query.redirect || '/';

      // Validate redirect path (security: prevent open redirect)
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
          // If redirectPath is relative, allow it
          if (!redirectPath.startsWith('/')) {
            return res.status(400).render('500', {
              error: 'Invalid redirect path',
            });
          }
        }
      }

      // Log session details for debugging
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

      // CRITICAL: Ensure session is saved one more time before redirect
      // This ensures the session cookie is definitely set in the response
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

      // Final verification - check if session is still set
      if (req.session.uid !== uid) {
        console.error(
          `[FlowPrompt SSO] WARNING: Session UID mismatch! Expected ${uid}, got ${req.session.uid}`,
        );
      }

      // CRITICAL: Before redirecting, ensure NodeBB's authentication middleware
      // will recognize the session. The issue is that after redirect, NodeBB's
      // middleware needs to load the user from the session.
      //
      // We've already set req.session.uid and req.user, but NodeBB's middleware
      // might need to run to fully authenticate the user.
      //
      // Try using an internal redirect through NodeBB's router to ensure
      // all middleware runs, or use a standard redirect and ensure the session
      // is properly loaded.

      console.log(
        `[FlowPrompt SSO] Sending HTTP redirect with session cookie...`,
      );

      // Set no-cache headers to prevent caching
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      // CRITICAL: Use an internal redirect (res.redirect with same host)
      // This ensures NodeBB's middleware chain runs and loads the user from session
      // The session cookie is already set in the response headers
      return res.redirect(302, redirectPath);
    } catch (err) {
      console.error('[FlowPrompt SSO] SSO error:', err);
      return res.status(401).render('500', {
        error: 'SSO authentication failed',
        message: err.message,
      });
    }
  },

  /**
   * Render admin settings page
   */
  async renderAdmin(req, res, next) {
    const self = Plugin;

    res.render('admin/plugins/flowprompt-sso', {
      title: 'FlowPrompt SSO Settings',
      config: self.config,
    });
  },

  /**
   * Save admin settings
   */
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

    // Reinitialize if needed
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
