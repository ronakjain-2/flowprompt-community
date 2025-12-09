# NodeBB FlowPrompt SSO Plugin

JWT-based Single Sign-On (SSO) plugin for NodeBB that integrates with FlowPrompt authentication.

## Features

- ✅ **RS256 JWT Verification** - Secure asymmetric signing
- ✅ **Automatic User Creation** - Creates users on first SSO login
- ✅ **Nonce Replay Protection** - Prevents token reuse
- ✅ **JWKS Support** - Automatic key discovery
- ✅ **Redis Integration** - Production-ready nonce storage
- ✅ **Session Management** - Seamless forum login

## Installation

```bash
cd /path/to/nodebb
npm install nodebb-plugin-flowprompt-sso
```

Or install from local directory:

```bash
npm install /path/to/nodebb-plugin-flowprompt-sso
```

## Configuration

1. **Activate Plugin**
   - Go to Admin Panel → Plugins
   - Find "FlowPrompt SSO" and click Activate

2. **Configure Settings**
   - Go to Admin Panel → Plugins → FlowPrompt SSO
   - Fill in:
     - FlowPrompt API URL (e.g., `https://api.flowprompt.com`)
     - Public Key (optional - will use JWKS if not provided)
     - JWT Issuer (default: `flowprompt`)
     - JWT Audience (default: `nodebb`)
     - Nonce Store Type (`memory` or `redis`)
     - Auto Create Users (enabled by default)

3. **Save Settings**

## How It Works

1. User clicks "Open Community" in FlowPrompt
2. FlowPrompt generates JWT token with user claims
3. Browser redirects to NodeBB: `/sso/jwt?token=<jwt>`
4. Plugin verifies JWT signature using public key
5. Plugin checks nonce (prevents replay)
6. Plugin finds or creates user (by email)
7. Plugin creates NodeBB session
8. User is redirected to forum (logged in)

## Requirements

- NodeBB 3.0.0+
- Node.js 18+
- FlowPrompt backend with SSO endpoints

## Dependencies

- `jsonwebtoken` - JWT verification
- `node-fetch` - HTTP requests
- `jwks-rsa` - JWKS key discovery

## Security

- **RS256 Signing** - Asymmetric encryption
- **Short-lived Tokens** - 60 second expiry
- **Nonce Tracking** - One-time use tokens
- **Redirect Validation** - Prevents open redirects

## Troubleshooting

### Token Verification Fails

- Check public key configuration
- Verify issuer and audience match FlowPrompt settings
- Check token hasn't expired (60s TTL)
- Ensure nonce wasn't already used

### Users Not Created

- Enable "Auto Create Users" in settings
- Check email claim in JWT token
- Review NodeBB logs for errors

### Session Not Created

- Check NodeBB session configuration
- Verify user was created/found successfully
- Check browser cookies are enabled

## License

MIT

