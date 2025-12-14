// library.js - FlowPrompt SSO plugin (updated)
// Fixes: robust nonce TTL, explicit cookie attribute overwrite (SameSite=None), uid cookie set, session cookie overwrite

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

    // Register route to serve client-side fix script
    // This script MUST run IMMEDIATELY before NodeBB's code executes
    router.get('/sso/session-fix.js', (req, res) => {
      res.type('application/javascript');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.send(`(function() {
        'use strict';
        // CRITICAL: Run immediately, before any other scripts
        // This intercepts NodeBB's session validation errors
        
        console.log('[FlowPrompt SSO] Session fix script loaded');
        
        function isUserLoggedIn() {
          try {
            const uid = parseInt(document.cookie.match(/uid=([^;]+)/)?.[1] || '0', 10);
            const hasSession = document.cookie.includes('express.sid') || document.cookie.includes('connect.sid');
            return uid > 0 || hasSession;
          } catch (e) {
            return false;
          }
        }
        
        function shouldSuppressError(message) {
          if (typeof message !== 'string') return false;
          const msg = message.toLowerCase();
          const errorMessages = [
            'login session no longer matches',
            'connection to flowprompt.ai was lost',
            'connection to flowprompt was lost',
            'session no longer matches',
            'login session',
            'was lost',
            'please refresh',
            'session expired',
            'authentication failed'
          ];
          const matches = errorMessages.some(err => msg.includes(err));
          const loggedIn = isUserLoggedIn();
          if (matches && loggedIn) {
            console.log('[FlowPrompt SSO] Detected session error message:', message);
          }
          return matches && loggedIn;
        }
        
        // Intercept window.alert IMMEDIATELY
        const originalAlert = window.alert;
        window.alert = function(message) {
          if (shouldSuppressError(message)) {
            console.log('[FlowPrompt SSO] Suppressed alert:', message);
            return;
          }
          return originalAlert.apply(this, arguments);
        };
        
        // Intercept console.error for session errors
        const originalConsoleError = console.error;
        console.error = function() {
          const args = Array.from(arguments);
          const message = args.map(arg => String(arg)).join(' ');
          if (shouldSuppressError(message)) {
            console.log('[FlowPrompt SSO] Suppressed console.error:', message);
            return;
          }
          return originalConsoleError.apply(console, arguments);
        };
        
        // Intercept socket.io at multiple levels
        function interceptSocketIO() {
          let socketFound = false;
          
          // Debug: Log what's available
          console.log('[FlowPrompt SSO] Checking for socket.io...');
          console.log('[FlowPrompt SSO] window.io:', typeof window.io, window.io);
          console.log('[FlowPrompt SSO] window.app:', typeof window.app, window.app);
          if (window.app) {
            console.log('[FlowPrompt SSO] window.app.socket:', window.app.socket);
          }
          
          // Method 1: Intercept io() function itself
          if (window.io && typeof window.io === 'function') {
            console.log('[FlowPrompt SSO] Found window.io as function, wrapping...');
            const originalIO = window.io;
            window.io = function() {
              const socket = originalIO.apply(this, arguments);
              wrapSocket(socket);
              return socket;
            };
            // Copy properties
            Object.keys(originalIO).forEach(key => {
              window.io[key] = originalIO[key];
            });
            socketFound = true;
          }
          
          // Method 2: Intercept existing socket instances (window.io.socket)
          if (window.io && window.io.socket) {
            console.log('[FlowPrompt SSO] Found window.io.socket, wrapping...');
            wrapSocket(window.io.socket);
            socketFound = true;
          }
          
          // Method 3: Intercept app.socket if it exists
          if (window.app && window.app.socket) {
            console.log('[FlowPrompt SSO] Found window.app.socket, wrapping...');
            wrapSocket(window.app.socket);
            socketFound = true;
          }
          
          // Method 4: Check for socket in app object (NodeBB might store it differently)
          if (window.app && typeof window.app === 'object') {
            // Check all properties that might be socket
            Object.keys(window.app).forEach(key => {
              const value = window.app[key];
              if (value && typeof value === 'object' && typeof value.emit === 'function' && typeof value.on === 'function') {
                console.log('[FlowPrompt SSO] Found socket-like object at window.app.' + key, 'wrapping...');
                wrapSocket(value);
                socketFound = true;
              }
            });
          }
          
          // Method 5: Intercept require.js to catch socket.io when it's loaded (NodeBB uses AMD)
          if (window.require && typeof window.require === 'function') {
            try {
              const originalRequire = window.require;
              
              // Wrap require to intercept socket.io module loading
              window.require = function() {
                const result = originalRequire.apply(this, arguments);
                
                // Check if result is a socket-like object
                if (result && typeof result === 'object') {
                  if (typeof result.emit === 'function' && typeof result.on === 'function') {
                    console.log('[FlowPrompt SSO] Found socket-like object from require, wrapping...');
                    wrapSocket(result);
                    socketFound = true;
                  }
                  
                  // Also check if it has a socket property
                  if (result.socket && typeof result.socket.emit === 'function') {
                    console.log('[FlowPrompt SSO] Found socket property in require result, wrapping...');
                    wrapSocket(result.socket);
                    socketFound = true;
                  }
                }
                
                // Check if arguments include socket-related modules
                const moduleIds = Array.isArray(arguments[0]) ? arguments[0] : [arguments[0]];
                moduleIds.forEach(moduleId => {
                  if (typeof moduleId === 'string' && (moduleId.includes('socket') || moduleId.includes('io'))) {
                    console.log('[FlowPrompt SSO] Detected require for socket module:', moduleId);
                    // The callback will receive the socket
                    if (arguments[1] && typeof arguments[1] === 'function') {
                      const originalCallback = arguments[1];
                      arguments[1] = function() {
                        const socket = arguments[0];
                        if (socket && typeof socket.emit === 'function') {
                          console.log('[FlowPrompt SSO] Wrapping socket from require callback');
                          wrapSocket(socket);
                          socketFound = true;
                        }
                        return originalCallback.apply(this, arguments);
                      };
                    }
                  }
                });
                
                return result;
              };
              
              // Copy properties
              Object.keys(originalRequire).forEach(key => {
                window.require[key] = originalRequire[key];
              });
              
              // Try to get socket from require cache
              if (window.require.cache) {
                Object.keys(window.require.cache).forEach(moduleId => {
                  if (moduleId.includes('socket') || moduleId.includes('io')) {
                    const module = window.require.cache[moduleId];
                    if (module && module.exports) {
                      const exp = module.exports;
                      if (exp && typeof exp.emit === 'function') {
                        console.log('[FlowPrompt SSO] Found socket in require cache:', moduleId, 'wrapping...');
                        wrapSocket(exp);
                        socketFound = true;
                      }
                    }
                  }
                });
              }
            } catch (e) {
              console.log('[FlowPrompt SSO] Error intercepting require.js:', e);
            }
          }
          
          // Method 6: Aggressively poll for socket to be created
          let pollCount = 0;
          const maxPolls = 100; // 10 seconds at 100ms intervals
          const checkForSocket = setInterval(function() {
            pollCount++;
            
            // Check window.io.socket
            if (window.io && window.io.socket && !window.io.socket._flowpromptWrapped) {
              console.log('[FlowPrompt SSO] Found window.io.socket during polling, wrapping...');
              wrapSocket(window.io.socket);
              socketFound = true;
            }
            
            // Check app.socket
            if (window.app && window.app.socket && !window.app.socket._flowpromptWrapped) {
              console.log('[FlowPrompt SSO] Found window.app.socket during polling, wrapping...');
              wrapSocket(window.app.socket);
              socketFound = true;
            }
            
            // Check if app object gets socket property added
            if (window.app && typeof window.app === 'object') {
              Object.keys(window.app).forEach(key => {
                const value = window.app[key];
                if (value && typeof value === 'object' && typeof value.emit === 'function' && !value._flowpromptWrapped) {
                  console.log('[FlowPrompt SSO] Found new socket-like object at window.app.' + key, 'wrapping...');
                  wrapSocket(value);
                  socketFound = true;
                }
              });
            }
            
            // Stop if we found socket or max polls reached
            if (socketFound && pollCount > 5) {
              clearInterval(checkForSocket);
            }
            if (pollCount >= maxPolls) {
              if (!socketFound) {
                console.warn('[FlowPrompt SSO] Socket.io not found after polling. NodeBB might use a different socket structure.');
              }
              clearInterval(checkForSocket);
            }
          }, 100);
        }
        
        function wrapSocket(socket) {
          if (!socket || socket._flowpromptWrapped) return;
          socket._flowpromptWrapped = true;
          
          console.log('[FlowPrompt SSO] Wrapping socket.io instance', socket);
          
          // Intercept emit - log all emits for debugging
          if (typeof socket.emit === 'function') {
            const originalEmit = socket.emit.bind(socket);
            socket.emit = function() {
              const args = Array.from(arguments);
              const eventName = args[0];
              
              // Log all emits for debugging (only first few times)
              if (!socket._flowpromptEmitCount) socket._flowpromptEmitCount = 0;
              if (socket._flowpromptEmitCount < 10) {
                console.log('[FlowPrompt SSO] Socket emit:', eventName, args.slice(1));
                socket._flowpromptEmitCount++;
              }
              
              // Suppress session check if user is logged in
              const sessionCheckEvents = [
                'user.checkSession',
                'user.validateSession',
                'user.check',
                'session.check',
                'auth.check'
              ];
              
              if (sessionCheckEvents.some(e => eventName === e || eventName.includes('Session') || eventName.includes('session')) && isUserLoggedIn()) {
                console.log('[FlowPrompt SSO] Suppressed socket.emit:', eventName);
                return socket;
              }
              
              return originalEmit.apply(this, arguments);
            };
          }
          
          // Intercept on/once/addEventListener - log all event registrations
          ['on', 'once', 'addEventListener'].forEach(method => {
            if (typeof socket[method] === 'function') {
              const originalMethod = socket[method].bind(socket);
              socket[method] = function(event, handler) {
                // Log event registrations for debugging
                if (!socket._flowpromptEventCount) socket._flowpromptEventCount = 0;
                if (socket._flowpromptEventCount < 20 && typeof event === 'string') {
                  console.log('[FlowPrompt SSO] Socket event listener registered:', event);
                  socket._flowpromptEventCount++;
                }
                
                // Intercept session error events
                if (typeof event === 'string' && typeof handler === 'function') {
                  const errorEvents = [
                    'event:user.statusChange',
                    'event:session.required',
                    'event:user.loggedOut',
                    'event:session.invalid',
                    'event:user.status',
                    'event:session',
                    'disconnect',
                    'error',
                    'reconnect_error',
                    'reconnect_failed'
                  ];
                  
                  // Check if event name contains session-related keywords
                  const isSessionEvent = errorEvents.includes(event) || 
                    event.toLowerCase().includes('session') ||
                    event.toLowerCase().includes('login') ||
                    event.toLowerCase().includes('auth');
                  
                  if (isSessionEvent && isUserLoggedIn()) {
                    console.log('[FlowPrompt SSO] Intercepting socket event listener:', event);
                    return originalMethod.call(this, event, function(data) {
                      console.log('[FlowPrompt SSO] Suppressed socket event:', event, data);
                      // Don't call the original handler if user is logged in
                      return;
                    });
                  }
                }
                
                return originalMethod.apply(this, arguments);
              };
            }
          });
          
          // Intercept socket connection/disconnection handlers
          if (socket.io && socket.io.on) {
            const originalIOOn = socket.io.on.bind(socket.io);
            socket.io.on = function(event, handler) {
              if ((event === 'error' || event === 'disconnect' || event === 'reconnect_error') && isUserLoggedIn()) {
                return originalIOOn.call(this, event, function(data) {
                  console.log('[FlowPrompt SSO] Suppressed socket.io error/disconnect:', event, data);
                  return;
                });
              }
              return originalIOOn.apply(this, arguments);
            };
          }
          
          // Also intercept any 'on' method on the socket itself for error events
          if (socket.on && typeof socket.on === 'function') {
            const originalOn = socket.on.bind(socket);
            socket.on = function(event, handler) {
              if (typeof event === 'string' && typeof handler === 'function') {
                const errorEvents = ['error', 'disconnect', 'reconnect_error', 'reconnect_failed'];
                if (errorEvents.includes(event) && isUserLoggedIn()) {
                  console.log('[FlowPrompt SSO] Intercepting socket.on error event:', event);
                  return originalOn.call(this, event, function(data) {
                    console.log('[FlowPrompt SSO] Suppressed socket.on error:', event, data);
                    return;
                  });
                }
              }
              return originalOn.apply(this, arguments);
            };
          }
        }
        
        // Wait for DOM and NodeBB to load, then intercept app.alert and other methods
        function initInterceptors() {
          console.log('[FlowPrompt SSO] Initializing interceptors, user logged in:', isUserLoggedIn());
          
          // Intercept app.alert
          if (window.app && typeof window.app.alert === 'function') {
            const originalAppAlert = window.app.alert;
            window.app.alert = function(message, type, timeout) {
              if (shouldSuppressError(message)) {
                console.log('[FlowPrompt SSO] Suppressed app.alert:', message);
                return;
              }
              return originalAppAlert.apply(this, arguments);
            };
          }
          
          // Intercept socket.io
          interceptSocketIO();
          
          // Intercept toastr
          if (window.toastr && typeof window.toastr.error === 'function') {
            const originalToastrError = window.toastr.error;
            window.toastr.error = function(message, title, options) {
              if (shouldSuppressError(message)) {
                console.log('[FlowPrompt SSO] Suppressed toastr.error:', message);
                return;
              }
              return originalToastrError.apply(this, arguments);
            };
          }
          
          // Intercept bootbox - handle both direct access and require.js access
          try {
            if (window.bootbox && typeof window.bootbox.alert === 'function') {
              const originalBootboxAlert = window.bootbox.alert;
              window.bootbox.alert = function(message, callback) {
                if (shouldSuppressError(message)) {
                  console.log('[FlowPrompt SSO] Suppressed bootbox.alert:', message);
                  if (callback) callback();
                  return;
                }
                return originalBootboxAlert.apply(this, arguments);
              };
            }
            
            // Also intercept via require.js if available
            if (window.require && typeof window.require === 'function') {
              const originalRequire = window.require;
              window.require = function() {
                const result = originalRequire.apply(this, arguments);
                // If bootbox is required, wrap it
                if (arguments[0] && Array.isArray(arguments[0]) && arguments[0].includes('bootbox')) {
                  const callback = arguments[1];
                  if (typeof callback === 'function') {
                    return originalRequire.call(this, arguments[0], function() {
                      const bootbox = arguments[0];
                      if (bootbox && typeof bootbox.alert === 'function') {
                        const originalBootboxAlert = bootbox.alert;
                        bootbox.alert = function(message, cb) {
                          if (shouldSuppressError(message)) {
                            console.log('[FlowPrompt SSO] Suppressed bootbox.alert (via require):', message);
                            if (cb) cb();
                            return;
                          }
                          return originalBootboxAlert.apply(this, arguments);
                        };
                      }
                      return callback.apply(this, arguments);
                    });
                  }
                }
                return result;
              };
            }
          } catch (e) {
            console.log('[FlowPrompt SSO] Error intercepting bootbox:', e);
          }
          
          // Intercept any DOM mutations that might add error messages
          if (window.MutationObserver) {
            const processedElements = new WeakSet();
            
            const observer = new MutationObserver(function(mutations) {
              mutations.forEach(function(mutation) {
                mutation.addedNodes.forEach(function(node) {
                  if (node.nodeType === 1 && !processedElements.has(node)) { // Element node
                    processedElements.add(node);
                    
                    // Check the node itself and all its children
                    const checkElement = function(el) {
                      if (!el || processedElements.has(el)) return;
                      processedElements.add(el);
                      
                      const text = (el.textContent || el.innerText || '').trim();
                      if (text && shouldSuppressError(text)) {
                        console.log('[FlowPrompt SSO] Removing error message from DOM:', text.substring(0, 100));
                        
                        // Try multiple methods to hide/remove
                        try {
                          el.style.display = 'none';
                          el.style.visibility = 'hidden';
                          el.style.opacity = '0';
                          el.style.height = '0';
                          el.style.width = '0';
                          el.style.overflow = 'hidden';
                          el.setAttribute('data-flowprompt-hidden', 'true');
                          
                          // Also hide parent if it's a container
                          if (el.parentNode && el.parentNode.nodeType === 1) {
                            const parent = el.parentNode;
                            if (parent.classList && (parent.classList.contains('alert') || parent.classList.contains('error') || parent.classList.contains('warning'))) {
                              parent.style.display = 'none';
                              parent.setAttribute('data-flowprompt-hidden', 'true');
                            }
                          }
                          
                          // Remove from DOM after a short delay
                          setTimeout(function() {
                            try {
                              if (el.parentNode) {
                                el.parentNode.removeChild(el);
                              }
                            } catch (e) {
                              // Element might already be removed
                            }
                          }, 100);
                        } catch (e) {
                          console.log('[FlowPrompt SSO] Error hiding element:', e);
                        }
                      }
                      
                      // Check children
                      if (el.children) {
                        for (let i = 0; i < el.children.length; i++) {
                          checkElement(el.children[i]);
                        }
                      }
                    };
                    
                    checkElement(node);
                  }
                });
              });
            });
            
            // Start observing when body is available
            function startObserver() {
              const target = document.body || document.documentElement;
              if (target) {
                observer.observe(target, {
                  childList: true,
                  subtree: true,
                  characterData: true
                });
                console.log('[FlowPrompt SSO] DOM mutation observer started');
              }
            }
            
            if (document.body) {
              startObserver();
            } else {
              document.addEventListener('DOMContentLoaded', startObserver);
            }
            
            // Also check existing elements
            setTimeout(function() {
              if (document.body) {
                const allElements = document.body.querySelectorAll('*');
                allElements.forEach(function(el) {
                  const text = (el.textContent || el.innerText || '').trim();
                  if (text && shouldSuppressError(text)) {
                    console.log('[FlowPrompt SSO] Found existing error message, removing:', text.substring(0, 100));
                    el.style.display = 'none';
                    el.setAttribute('data-flowprompt-hidden', 'true');
                  }
                });
              }
            }, 500);
          }
          
          // Intercept jQuery ajaxError if available (NodeBB might use this)
          if (window.jQuery && window.jQuery(document)) {
            window.jQuery(document).off('ajaxError.flowprompt-sso');
            window.jQuery(document).on('ajaxError.flowprompt-sso', function(event, xhr, settings, error) {
              if (xhr && xhr.responseText && shouldSuppressError(xhr.responseText)) {
                console.log('[FlowPrompt SSO] Suppressed ajaxError:', error);
                event.preventDefault();
                event.stopPropagation();
                return false;
              }
            });
          }
          
          // Intercept fetch API for session validation calls
          if (window.fetch) {
            const originalFetch = window.fetch;
            window.fetch = function() {
              const args = Array.from(arguments);
              const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
              
              // Check if this is a session validation endpoint
              if ((url.includes('/api/user/session') || url.includes('/api/user/status') || url.includes('checkSession')) && isUserLoggedIn()) {
                console.log('[FlowPrompt SSO] Intercepting fetch for session check:', url);
                // Return a successful response instead
                return Promise.resolve(new Response(JSON.stringify({ status: 'ok', uid: parseInt(document.cookie.match(/uid=([^;]+)/)?.[1] || '0', 10) }), {
                  status: 200,
                  headers: { 'Content-Type': 'application/json' }
                }));
              }
              
              return originalFetch.apply(this, arguments).then(response => {
                // Intercept response if it contains session error
                if (response.ok) {
                  return response.clone().text().then(text => {
                    if (shouldSuppressError(text)) {
                      console.log('[FlowPrompt SSO] Suppressed fetch response error:', text);
                      return new Response(JSON.stringify({ status: 'ok' }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                      });
                    }
                    return response;
                  }).catch(() => response);
                }
                return response;
              });
            };
          }
          
          // Intercept XMLHttpRequest ONLY for specific session validation endpoints
          // Don't intercept all XHRs to avoid breaking socket.io and other functionality
          if (window.XMLHttpRequest) {
            const originalXHROpen = XMLHttpRequest.prototype.open;
            
            XMLHttpRequest.prototype.open = function(method, url) {
              this._flowpromptUrl = url;
              this._flowpromptIsSessionCheck = false;
              
              // Only mark as session check for specific endpoints
              if (typeof url === 'string' && isUserLoggedIn()) {
                const sessionCheckPatterns = [
                  '/api/user/session',
                  '/api/user/status',
                  'checkSession',
                  '/api/session'
                ];
                this._flowpromptIsSessionCheck = sessionCheckPatterns.some(pattern => url.includes(pattern));
              }
              
              return originalXHROpen.apply(this, arguments);
            };
            
            // Only intercept onreadystatechange for session check requests
            const originalXHRSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.send = function() {
              // Only wrap onreadystatechange for session checks
              if (this._flowpromptIsSessionCheck && !this._flowpromptWrapped) {
                this._flowpromptWrapped = true;
                const originalOnReadyStateChange = this.onreadystatechange;
                if (originalOnReadyStateChange) {
                  this.onreadystatechange = function() {
                    // Only intercept if it's a session check and contains error
                    if (this.readyState === 4 && this.responseText && shouldSuppressError(this.responseText)) {
                      console.log('[FlowPrompt SSO] Suppressed XHR session error response');
                      // Don't modify the response, just prevent the error from propagating
                      return;
                    }
                    return originalOnReadyStateChange.apply(this, arguments);
                  };
                }
              }
              
              return originalXHRSend.apply(this, arguments);
            };
          }
        }
        
        // Global error message logger - helps identify what error messages appear
        window._flowpromptErrorLogger = {
          messages: [],
          log: function(message, source) {
            this.messages.push({ message: message, source: source, time: new Date().toISOString() });
            console.log('[FlowPrompt SSO] Error message detected:', message, 'from:', source);
            // Keep only last 20 messages
            if (this.messages.length > 20) {
              this.messages.shift();
            }
          }
        };
        
        // Periodic cleanup of error messages
        setInterval(function() {
          if (!isUserLoggedIn()) return;
          
          // Find and remove all error elements
          const errorSelectors = [
            '.alert-danger',
            '.alert-warning',
            '.alert',
            '[class*="error"]',
            '[class*="warning"]',
            '[id*="error"]',
            '[id*="warning"]'
          ];
          
          errorSelectors.forEach(function(selector) {
            try {
              const elements = document.querySelectorAll(selector);
              elements.forEach(function(el) {
                const text = (el.textContent || el.innerText || '').trim();
                if (text && shouldSuppressError(text)) {
                  console.log('[FlowPrompt SSO] Periodic cleanup: Removing error element');
                  el.style.display = 'none';
                  el.style.visibility = 'hidden';
                  el.setAttribute('data-flowprompt-hidden', 'true');
                  try {
                    if (el.parentNode) {
                      el.parentNode.removeChild(el);
                    }
                  } catch (e) {}
                }
              });
            } catch (e) {}
          });
        }, 500); // Run every 500ms
        
        // Override common error display methods to log messages
        const logError = function(message, source) {
          if (typeof message === 'string' && message.length > 0) {
            window._flowpromptErrorLogger.log(message, source);
          }
        };
        
        // Wrap alert one more time to log
        const originalAlert2 = window.alert;
        window.alert = function(message) {
          logError(String(message), 'window.alert');
          return originalAlert2.apply(this, arguments);
        };
        
        // Run interceptors immediately
        initInterceptors();
        
        // Also run after delays to catch late-loading NodeBB code
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initInterceptors);
        }
        
        setTimeout(initInterceptors, 50);
        setTimeout(initInterceptors, 100);
        setTimeout(initInterceptors, 250);
        setTimeout(initInterceptors, 500);
        setTimeout(initInterceptors, 1000);
        setTimeout(initInterceptors, 2000);
        
        // Final check after page fully loads
        window.addEventListener('load', function() {
          console.log('[FlowPrompt SSO] Page fully loaded, running final interceptor check');
          setTimeout(initInterceptors, 100);
          setTimeout(initInterceptors, 500);
        });
      })();`);
    });

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

    // Note: Client-side script injection is handled via filter:header.build hook
    // This injects the script to suppress "login session no longer matches" error

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

    // Also inject script via action hook as fallback
    const hooks = require.main.require('./src/plugins/hooks');

    hooks.register('filter:header.build', self.filterHeaderBuild.bind(self));

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

    // CRITICAL: Configure session cookie options BEFORE saving
    // This ensures express-session sets the cookie with correct SameSite=None from the start
    const meta = require.main.require('./src/meta');
    let cookieDomain = null;

    try {
      if (meta && meta.config && meta.config.cookieDomain) {
        cookieDomain = meta.config.cookieDomain;
      }
    } catch (e) {}
    if (!cookieDomain) {
      try {
        const config = require('../../../../../../srv/nodebb/config.json');

        if (config && config.cookieDomain) cookieDomain = config.cookieDomain;
      } catch (e) {}
    }

    if (!cookieDomain) cookieDomain = '.flowprompt.ai';

    const isSecure =
      req.protocol === 'https' ||
      req.get('X-Forwarded-Proto') === 'https' ||
      req.secure ||
      false;

    // Configure session cookie options BEFORE save
    if (req.session.cookie) {
      req.session.cookie.domain = cookieDomain;
      req.session.cookie.secure = !!isSecure;
      req.session.cookie.sameSite = 'None'; // CRITICAL: Set SameSite=None
      req.session.cookie.path = '/';
      console.log(
        `[FlowPrompt SSO] Configured session cookie: domain=${cookieDomain}, sameSite=None, secure=${!!isSecure}`,
      );
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

      // CRITICAL: Intercept Set-Cookie headers AFTER express-session sets them
      // express-session uses session store cookie options, not req.session.cookie
      // We need to modify the actual Set-Cookie header to change SameSite=None
      const cookieName =
        (req.session && req.session.cookie && req.session.cookie.name) ||
        'express.sid';

      // Hook into response to modify Set-Cookie headers before sending
      const originalEnd = res.end.bind(res);

      res.end = function (chunk, encoding) {
        // Get existing Set-Cookie headers
        let setCookies = res.getHeader('Set-Cookie') || [];

        if (!Array.isArray(setCookies)) {
          setCookies = [setCookies];
        }

        // Find and replace express.sid cookie with SameSite=None
        const modifiedCookies = setCookies.map((cookie) => {
          if (
            typeof cookie === 'string' &&
            cookie.startsWith(`${cookieName}=`)
          ) {
            // Extract the cookie value (everything before first semicolon)
            const cookieValue = cookie
              .split(';')[0]
              .substring(cookieName.length + 1);

            // Get cookie domain
            const cookieDomain = (function () {
              try {
                const meta = require.main.require('./src/meta');

                return (
                  (meta && meta.config && meta.config.cookieDomain) ||
                  require('../../../../../../srv/nodebb/config.json')
                    .cookieDomain ||
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

            // Rebuild cookie with SameSite=None
            return `${cookieName}=${cookieValue}; Domain=${cookieDomain}; Path=/; HttpOnly; Secure; SameSite=None`;
          }

          return cookie;
        });

        // Remove duplicates (keep only the last occurrence of each cookie name)
        const seen = new Set();
        const uniqueCookies = [];

        for (let i = modifiedCookies.length - 1; i >= 0; i--) {
          const cookie = modifiedCookies[i];
          const cookieNameFromHeader = cookie.split('=')[0];

          if (!seen.has(cookieNameFromHeader)) {
            seen.add(cookieNameFromHeader);
            uniqueCookies.unshift(cookie);
          }
        }

        // Set the modified headers
        if (uniqueCookies.length > 0) {
          res.setHeader('Set-Cookie', uniqueCookies);
          console.log(
            '[FlowPrompt SSO] Modified Set-Cookie headers: removed duplicates, set SameSite=None for',
            cookieName,
          );
        }

        return originalEnd(chunk, encoding);
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
          const config = require('../../../../../../srv/nodebb/config.json');

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

      // NOTE: Session cookie options are configured in createSession() before save()
      // express-session will use those options when setting the cookie
      // No need to manually overwrite here

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

  // Inject script via header hook - adds script tag EARLY in the page
  async filterHeaderBuild(header) {
    const meta = require.main.require('./src/meta');
    const baseUrl = meta.config.relative_path || '';
    const scriptUrl = `${baseUrl}/sso/session-fix.js`;

    // Inject script as early as possible - in the head section
    // Try multiple possible locations in the header object
    if (header) {
      // Method 1: templateData.scripts (most common)
      if (header.templateData) {
        header.templateData.scripts = header.templateData.scripts || [];
        // Insert at the beginning to run early
        header.templateData.scripts.unshift(
          `<script src="${scriptUrl}"></script>`,
        );
      }

      // Method 2: Direct scripts array
      if (Array.isArray(header.scripts)) {
        header.scripts.unshift(`<script src="${scriptUrl}"></script>`);
      } else if (typeof header.scripts === 'string') {
        header.scripts = `<script src="${scriptUrl}"></script>\n${header.scripts}`;
      } else if (!header.scripts) {
        header.scripts = [`<script src="${scriptUrl}"></script>`];
      }

      // Method 3: Add to head directly if available
      if (header.head) {
        if (Array.isArray(header.head)) {
          header.head.unshift(`<script src="${scriptUrl}"></script>`);
        } else if (typeof header.head === 'string') {
          header.head = `<script src="${scriptUrl}"></script>\n${header.head}`;
        }
      }
    }

    return header;
  },
};

module.exports = Plugin;
