# MCP Auth

OAuth 2.1 authorization for Model Context Protocol (MCP) servers in Rails applications.

## What is MCP Authorization?

The Model Context Protocol (MCP) is an open standard that enables AI assistants to securely connect to external data sources and tools. MCP Auth implements the [MCP Authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), providing OAuth 2.1-based authentication for MCP servers.

### Why OAuth for MCP?

MCP servers often need to access user data or perform actions on behalf of users. OAuth 2.1 provides:

- **Delegated Authorization**: Users can grant MCP clients access without sharing credentials
- **Scope-Based Permissions**: Fine-grained control over what data/actions are allowed
- **Token-Based Security**: Short-lived access tokens with automatic refresh
- **PKCE Protection**: Enhanced security for public clients (AI assistants)

## How MCP Auth Works

### Architecture Overview

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│                 │         │                  │         │                 │
│   MCP Client    │────────▶│  Your Rails App  │◀────────│   End User      │
│  (AI Assistant) │         │  (MCP Server +   │         │   (Browser)     │
│                 │         │   OAuth Server)  │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
      │                             │                             │
      │                             │                             │
      │  1. Discover OAuth Server   │                             │
      │────────────────────────────▶│                             │
      │                             │                             │
      │  2. Request Authorization   │                             │
      │────────────────────────────▶│                             │
      │                             │                             │
      │                             │   3. Show Consent Screen    │
      │                             │────────────────────────────▶│
      │                             │                             │
      │                             │   4. User Approves          │
      │                             │◀────────────────────────────│
      │                             │                             │
      │  5. Receive Auth Code       │                             │
      │◀────────────────────────────│                             │
      │                             │                             │
      │  6. Exchange for Token      │                             │
      │────────────────────────────▶│                             │
      │                             │                             │
      │  7. Access MCP Server       │                             │
      │────────────────────────────▶│                             │
```

### OAuth 2.1 Flow Sequence

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Server as MCP Server
    participant AuthServer as OAuth Server
    participant User as End User

    Note over Client,User: Discovery Phase
    Client->>Server: Request without token
    Server-->>Client: 401 + WWW-Authenticate header
    Client->>Server: GET /.well-known/oauth-protected-resource
    Server-->>Client: Protected Resource Metadata
    Client->>AuthServer: GET /.well-known/oauth-authorization-server
    AuthServer-->>Client: OAuth Server Metadata

    Note over Client,User: Authorization Phase
    Client->>Client: Generate PKCE challenge
    Client->>User: Open browser with authorization URL
    User->>AuthServer: Authorization request (+ PKCE challenge)
    AuthServer->>User: Show consent screen
    User->>AuthServer: Approve access
    AuthServer-->>User: Redirect with authorization code
    User->>Client: Return authorization code
    
    Note over Client,User: Token Exchange
    Client->>AuthServer: Exchange code for token (+ PKCE verifier)
    AuthServer->>AuthServer: Validate PKCE
    AuthServer-->>Client: Access token + Refresh token

    Note over Client,User: Access MCP Resources
    Client->>Server: MCP request + Bearer token
    Server->>Server: Validate token audience
    Server-->>Client: MCP response
```

### Key Security Features

1. **PKCE (Proof Key for Code Exchange)**: Required for all authorization flows
    - Prevents authorization code interception
    - Secure for public clients (AI assistants)

2. **Resource Indicators (RFC 8707)**: Token audience binding
    - Tokens are explicitly bound to your MCP server
    - Prevents token misuse across different services

3. **Token Rotation**: OAuth 2.1 requirement
    - Refresh tokens are rotated on each use
    - Limits impact of token theft

4. **Short-Lived Access Tokens**: Default 1 hour lifetime
    - Reduces security window for stolen tokens
    - Automatic refresh via refresh tokens

## Features

- ✅ **OAuth 2.1 Compliant** - Latest draft specification
- ✅ **PKCE Required** - S256 method for enhanced security
- ✅ **Dynamic Client Registration** - RFC 7591 support
- ✅ **Resource Indicators** - RFC 8707 for token audience binding
- ✅ **Protected Resource Metadata** - RFC 9728 for server discovery
- ✅ **Token Revocation** - RFC 7009 support
- ✅ **Token Introspection** - RFC 7662 support
- ✅ **OpenID Connect** - Basic OIDC Discovery support
- ✅ **Refresh Token Rotation** - OAuth 2.1 security requirement, with reuse detection
- ✅ **Secrets Hashed at Rest** - tokens, codes and client secrets stored as SHA-256 digests
- ✅ **Registration Policy** - https-or-loopback redirect URIs, optional allowlist, unknown scopes rejected
- ✅ **RS256 / ES256 Signing** - optional asymmetric JWTs with a JWKS endpoint and key rotation
- ✅ **Fully Configurable** - Paths, URLs, lifetimes, and user data
- ✅ **Beautiful Consent Screen** - Customizable UI

## Installation

```bash
# Add to Gemfile
gem 'mcp-auth'

# Install
bundle install

# Generate migrations and config
rails generate mcp:auth:install

# Run migrations
rails db:migrate
```

**Upgrading an existing install?** Don't re-run the install generator. Use
`rails generate mcp:auth:upgrade` (schema, before deploying) and, once every
server runs the new version, `rails generate mcp:auth:hash_secrets`. See the
0.6.0 "Upgrade" section in [CHANGELOG.md](CHANGELOG.md) for the exact order.

## Quick Start

### 1. Mount Routes

**CRITICAL**: Mount at the TOP of `config/routes.rb`:

```ruby
Rails.application.routes.draw do
  # Mount MCP Auth FIRST - before any catch-all routes
  mount Mcp::Auth::Engine => '/'
  
  # Then your other routes
  devise_for :users
  root to: 'dashboard#index'
  
  # ... rest of your routes
end
```

⚠️ **Why at the top?** The gem's routes (like `/.well-known/oauth-*` and `/oauth/*`) need to be registered before any catch-all routes or they'll be intercepted by your app's routing.

### 2. Configure MCP Auth

Edit `config/initializers/mcp_auth.rb`:

```ruby
Mcp::Auth.configure do |config|
  # OAuth secret for JWT signing (HS256) — required outside development/test,
  # and must not be secret_key_base. Generate with `rails secret`.
  config.oauth_secret = ENV['MCP_HMAC_SECRET']
  
  # Authorization server URL (optional - defaults to same as resource server)
  config.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)
  
  # Public origin of the MCP resource server (optional - defaults to the request
  # origin). Pins the token audience and protected-resource metadata URLs.
  config.mcp_server_url = ENV.fetch('MCP_SERVER_URL', nil)

  # MCP Server Path - where your MCP server is mounted
  # Change this if your MCP server is NOT at '/mcp'
  config.mcp_server_path = ENV.fetch('MCP_SERVER_PATH', '/mcp')
  
  # MCP Documentation URL (optional)
  # Default: {mcp_server_path}/docs (e.g., /mcp/docs)
  # Can be a path or full URL:
  config.mcp_docs_url = ENV.fetch('MCP_DOCS_URL', nil)
  # Examples:
  #   config.mcp_docs_url = '/docs/mcp-api'
  #   config.mcp_docs_url = 'https://docs.example.com/mcp'
  
  # Token lifetimes (in seconds)
  config.access_token_lifetime = 3600        # 1 hour
  config.refresh_token_lifetime = 2_592_000  # 30 days
  config.authorization_code_lifetime = 1800  # 30 minutes

  # User data fetcher - CUSTOMIZE THIS
  #
  # SECURITY: only NON-sensitive values are embedded into the access token (a
  # bearer JWT is decodable by anyone holding it and is stored at rest). Return
  # an api_key_id (an opaque reference) and resolve the matching secret
  # server-side from that id at request time. Never return a raw secret here —
  # any `api_key_secret` is intentionally ignored and NOT placed in the token.
  config.fetch_user_data = proc do |data|
    user = User.find(data[:user_id])
    org = Org.find(data[:org_id]) if data[:org_id]

    {
      email: user.email,
      api_key_id: org&.api_key&.id
    }
  rescue ActiveRecord::RecordNotFound
    { email: 'unknown@example.com', api_key_id: nil }
  end

  # Methods for authentication
  config.current_user_method = :current_user
  config.current_org_method = :current_org
end
```

### 3. Ensure Authentication Methods

Your `ApplicationController` should have these methods:

```ruby
class ApplicationController < ActionController::Base
  # For Devise users, these are already defined
  # For custom auth, implement these methods:
  
  def current_user
    # Your logic to get the currently logged-in user
    @current_user ||= User.find_by(id: session[:user_id])
  end

  def current_org
    # Your logic to get the current organization (if applicable)
    @current_org ||= current_user&.current_org
  end
end
```

**Login redirect:** when a user who isn't signed in reaches `/oauth/authorize`,
MCP Auth redirects to `main_app.new_user_session_path`, the route Devise defines.
Without Devise, define a route with that name that leads to your login page.

### 4. Set Environment Variables

```bash
# .env
MCP_HMAC_SECRET=your_secure_random_string_here
MCP_SERVER_PATH=/mcp               # or /api/mcp, /assistant/api, etc.
MCP_DOCS_URL=/docs/mcp             # optional
```

### 5. Restart Server

```bash
spring stop  # Clear spring cache
rails server
```

## OAuth Endpoints (Automatic)

MCP Auth provides these endpoints automatically:

### Discovery Endpoints

- `GET /.well-known/oauth-protected-resource` - RFC 9728 Protected Resource Metadata
- `GET /.well-known/oauth-authorization-server` - RFC 8414 Authorization Server Metadata
- `GET /.well-known/openid-configuration` - OpenID Connect Discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set (empty for HMAC)

### OAuth Flow Endpoints

- `GET/POST /oauth/authorize` - Authorization endpoint (PKCE required)
- `POST /oauth/approve` - Consent approval endpoint
- `POST /oauth/token` - Token endpoint (authorization_code, refresh_token)
- `POST /oauth/register` - Dynamic client registration (RFC 7591)
- `POST /oauth/revoke` - Token revocation (RFC 7009)
- `POST /oauth/introspect` - Token introspection (RFC 7662)
- `GET /oauth/userinfo` - OpenID Connect UserInfo endpoint

## Usage

### Protecting Your MCP Server

MCP Auth does **not** protect any route by itself. Include the resource-server
concern in the controller that serves your MCP endpoint:

```ruby
class McpController < ApplicationController
  include Mcp::Auth::ProtectedResource

  before_action :authenticate_mcp_token!
  before_action -> { require_mcp_scope!('mcp:write') }, only: :create
end
```

`authenticate_mcp_token!` checks the Bearer token's signature, expiry,
revocation status and audience (`mcp_server_url` or the request origin, plus
`mcp_server_path`). On failure it returns a 401 whose `WWW-Authenticate` header
points MCP clients at the protected-resource metadata (RFC 9728).
`require_mcp_scope!` returns a 403 `insufficient_scope` when a scope is missing.

If your MCP server is mounted as Rack middleware (not a controller), validate
the token yourself and build the same header:

```ruby
payload = Mcp::Auth::Services::TokenService.validate_access_token(
  token, resource: 'https://example.com/mcp'
)
unless payload
  headers = { 'WWW-Authenticate' => Mcp::Auth::ProtectedResource.www_authenticate('https://example.com') }
  return [401, headers, ['Unauthorized']]
end
```

### OAuth 2.1 Authorization Flow

#### 1. Register a Client (Dynamic Registration)

```bash
curl -X POST http://localhost:3000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["https://client.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "mcp:read mcp:write"
  }'
```

Response:
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "a1b2c3d4...",
  "client_id_issued_at": 1234567890,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp:read mcp:write",
  "token_endpoint_auth_method": "none",
  "client_name": "My MCP Client"
}
```

The `client_secret` is returned only once; only its hash is stored. Clients are
public (`none`, PKCE only) unless they register `token_endpoint_auth_method` as
`client_secret_basic` or `client_secret_post`, in which case the token endpoint
requires the secret.

#### 2. Authorization Request with PKCE

Generate PKCE parameters:

```javascript
// Generate code verifier (43-128 characters)
const codeVerifier = base64URLEncode(randomBytes(32));

// Generate code challenge
const codeChallenge = base64URLEncode(
  sha256(codeVerifier)
);
```

Redirect user to authorization URL:

```
GET /oauth/authorize?
  response_type=code&
  client_id=550e8400-e29b-41d4-a716-446655440000&
  redirect_uri=https://client.example.com/callback&
  scope=mcp:read+mcp:write&
  state=random_state_string&
  code_challenge=CODE_CHALLENGE&
  code_challenge_method=S256&
  resource=https://example.com/mcp
```

User will see consent screen and approve/deny access.

#### 3. Token Exchange

After user approves, exchange authorization code for tokens:

```bash
curl -X POST https://example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=https://client.example.com/callback" \
  -d "code_verifier=CODE_VERIFIER" \
  -d "client_id=550e8400-e29b-41d4-a716-446655440000" \
  -d "resource=https://example.com/mcp"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "a1b2c3d4e5f6...",
  "scope": "mcp:read mcp:write"
}
```

#### 4. Access Protected Resources

```bash
curl https://example.com/mcp/tools \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

#### 5. Refresh Token

When access token expires:

```bash
curl -X POST https://example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=a1b2c3d4e5f6..." \
  -d "client_id=550e8400-e29b-41d4-a716-446655440000"
```

### Helper Methods in Controllers

These read what `authenticate_mcp_token!` stored for the request, so they are
only set in controllers that run it (see above):

```ruby
class MyController < ApplicationController
  def index
    if mcp_authenticated?
      user_id = mcp_user_id      # User ID from token
      org_id = mcp_org_id        # Org ID from token
      email = mcp_email          # Email from token
      scope = mcp_scope          # Token scopes
      api_key = mcp_api_key      # API key if configured
      
      # Your logic here
      render json: { user_id: user_id, email: email }
    else
      render json: { error: 'Unauthorized' }, status: :unauthorized
    end
  end
end
```

Available helper methods:

- `mcp_authenticated?` - Returns true if request has valid token
- `mcp_user_id` - User ID from token
- `mcp_org_id` - Organization ID from token
- `mcp_email` - User email from token
- `mcp_scope` - Token scopes (space-separated string)
- `mcp_token` - The access token itself
- `mcp_api_key` - API key if configured in `fetch_user_data`

## Advanced Configuration

### Custom MCP Server Paths

If your MCP server is mounted at a different path:

```ruby
# config/initializers/mcp_auth.rb
config.mcp_server_path = '/api/v1/assistant'  # Custom path

# Your MCP server configuration
FastMcp.mount_in_rails(
  Rails.application,
  path_prefix: '/api/v1/assistant'  # Must match mcp_server_path
)
```

### Custom Documentation URL

Point to your API documentation:

```ruby
# Path-based (will be prefixed with your domain)
config.mcp_docs_url = '/docs/mcp-api'

# Full URL to external docs
config.mcp_docs_url = 'https://docs.example.com/mcp-api'

# Default (if not set): {mcp_server_path}/docs
# Example: /mcp/docs
```

### Custom Consent Screen

`rails generate mcp:auth:install` copies the consent page to
`app/views/mcp/auth/consent.html.erb`. That copy overrides the gem's view, so
edit it to match your branding. Optionally render it inside your app layout:

```ruby
# config/initializers/mcp_auth.rb
config.use_custom_consent_view = true          # render with layout 'application'
config.consent_view_path = 'mcp/auth/consent'  # the template to render
```

Variables available in the view:

- `@client_name` - Name the client registered (self-asserted; not verified)
- `@redirect_host` - Host the authorization code will be sent to. **Show it.**
- `@redirect_verified` / `@redirect_loopback` - Whether that host is in
  `verified_redirect_hosts`, or is a loopback address
- `@requested_scopes` - Array of hashes: `:key`, `:name`, `:description`,
  `:required`, `:pre_selected`
- `@authorization_params` - OAuth parameters to send back unchanged

The approve form must POST the user's chosen scopes as `scopes[]` (required
scopes included) together with `approved=true`; with no scopes the request is
rejected. A minimal example:

```erb
<h1><%= @client_name %> wants to access your account</h1>
<p>You will be sent back to <strong><%= @redirect_host %></strong></p>
<% unless @redirect_verified || @redirect_loopback %>
  <p><strong>Unverified application.</strong> Only continue if you started this connection.</p>
<% end %>

<%= form_with url: oauth_approve_path, method: :post, local: true do |f| %>
  <% @authorization_params.each do |key, value| %>
    <%= f.hidden_field key, value: value, id: nil %>
  <% end %>
  <% @requested_scopes.each do |scope| %>
    <label>
      <%= check_box_tag 'scopes[]', scope[:key], scope[:required] || scope[:pre_selected],
                        id: nil, disabled: scope[:required] %>
      <%= scope[:name] %> — <%= scope[:description] %>
    </label>
    <%# disabled checkboxes aren't submitted, so send required scopes separately %>
    <%= hidden_field_tag 'scopes[]', scope[:key], id: nil if scope[:required] %>
  <% end %>
  <%= f.button 'Allow', name: 'approved', value: 'true' %>
<% end %>

<%= form_with url: oauth_approve_path, method: :post, local: true do |f| %>
  <% @authorization_params.each do |key, value| %>
    <%= f.hidden_field key, value: value, id: nil %>
  <% end %>
  <%= f.hidden_field :approved, value: 'false' %>
  <%= f.button 'Deny' %>
<% end %>
```

### Scopes and Per-User Policy

Register the scopes your MCP server understands (requests naming any other
scope are rejected unless `strict_scope_validation = false`):

```ruby
config.register_scope 'mcp:read',  name: 'Read Access',  description: 'Read your data', required: true
config.register_scope 'mcp:write', name: 'Write Access', description: 'Modify data on your behalf'
```

To restrict which scopes a given user may grant, set a policy. It hides
scopes on the consent screen **and** is enforced when the code is issued:

```ruby
config.validate_scope_for_user = proc do |user, org, scope|
  scope != 'mcp:admin' || user.admin?
end
```

### Client Registration Policy

`/oauth/register` is open (RFC 7591), so limit what a registered client can do:

```ruby
# Only these redirect URIs can register. Strings match exactly; Regexps must
# match the WHOLE URI (end with .* to allow any path).
config.allowed_redirect_uri_patterns = [
  %r{https://claude\.ai/api/mcp/auth_callback}
]
config.allow_loopback_redirects = true             # localhost / 127.0.0.1 / [::1], any port
config.verified_redirect_hosts = %w[claude.ai]     # others show "Unverified application"
config.strict_scope_validation = true              # reject unknown scopes
```

Plain `http://` redirect URIs are always rejected except on loopback hosts.

### Token Signing (RS256 / ES256)

Tokens are signed with HS256 and `oauth_secret` by default. To let other
services verify tokens without the shared secret, use asymmetric keys. The
public keys are published at `/.well-known/jwks.json`:

```ruby
config.token_signing_algorithm = 'RS256' # or 'ES256'
config.token_signing_private_key = ENV.fetch('MCP_JWT_PRIVATE_KEY')
# Key rotation: keep previous public keys so issued tokens still verify
config.token_signing_additional_public_keys = [ENV['MCP_JWT_PREVIOUS_PUBLIC_KEY']].compact
```

### Separate Authorization Server

If you want to use a separate authorization server:

```ruby
# config/initializers/mcp_auth.rb
config.authorization_server_url = 'https://auth.example.com'
# Public origin of THIS app's MCP endpoint (the token audience). Optional —
# defaults to the request origin — but set it to pin the audience and metadata
# URLs against a forged Host header.
config.mcp_server_url = 'https://api.example.com'
```

This is useful for:
- Microservices architecture
- Multiple resource servers sharing one auth server
- Enterprise SSO integration

## Testing

### Test the Installation

```bash
# Start your server
rails server

# Test discovery endpoints
curl http://localhost:3000/.well-known/oauth-protected-resource
curl http://localhost:3000/.well-known/oauth-authorization-server

# Register a test client
curl -X POST http://localhost:3000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

### In Your Test Suite

Create tokens directly in tests:

```ruby
RSpec.describe 'MCP API', type: :request do
  let(:user) { create(:user) }
  let(:org) { create(:org) }
  
  # Request specs use the host www.example.com, and the token audience must
  # match the resource your controller expects (mcp_server_url, or the request
  # origin, plus mcp_server_path).
  let(:access_token) do
    token_data = {
      client_id: 'test-client',
      scope: 'mcp:read mcp:write',
      user_id: user.id,
      org_id: org.id,
      resource: 'http://www.example.com/mcp'
    }

    Mcp::Auth::Services::TokenService.generate_access_token(
      token_data,
      base_url: 'http://www.example.com'
    )
  end
  
  it 'allows authenticated requests' do
    get '/mcp/tools', headers: {
      'Authorization' => "Bearer #{access_token}"
    }
    
    expect(response).to have_http_status(:success)
  end
  
  it 'rejects unauthenticated requests' do
    get '/mcp/tools'
    
    expect(response).to have_http_status(:unauthorized)
  end
end
```

## Rake Tasks

MCP Auth includes helpful maintenance tasks:

```bash
# Clean up expired tokens and codes (run daily)
rake mcp_auth:cleanup

# Show token statistics
rake mcp_auth:stats

# Revoke all tokens for a specific client
rake mcp_auth:revoke_client_tokens[CLIENT_ID]

# Revoke all tokens for a specific user
rake mcp_auth:revoke_user_tokens[USER_ID]

# Check the database schema and signing secret (exits non-zero on problems)
rake mcp_auth:doctor
```

### Scheduled Cleanup

Add to your scheduler (cron, whenever, sidekiq-cron):

```ruby
# config/schedule.rb (whenever gem)
every 1.day, at: '3:00 am' do
  rake 'mcp_auth:cleanup'
end
```

## Security Best Practices

### 1. Use Strong Secrets

```bash
# Generate a strong secret
rails secret

# Set in environment
export MCP_HMAC_SECRET="your-256-bit-secret-here"
```

Outside development/test, HS256 signing fails if this secret is unset or equal
to `secret_key_base`. `rake mcp_auth:doctor` checks it.

### 2. Always Use HTTPS in Production

```ruby
# config/environments/production.rb
config.force_ssl = true
```

MCP Auth rejects plain-HTTP requests to the OAuth endpoints outside development/test.

### Pin Your Public URLs

Discovery metadata, the token issuer and the token audience come from
`authorization_server_url` and `mcp_server_url`. When they're unset, the request's
Host header is used, so set them or restrict `config.hosts`:

```ruby
config.authorization_server_url = 'https://example.com'
config.mcp_server_url = 'https://example.com'
```

### 3. Keep Token Lifetimes Short

```ruby
# Recommended settings
config.access_token_lifetime = 3600        # 1 hour
config.refresh_token_lifetime = 2_592_000  # 30 days
config.authorization_code_lifetime = 600   # 10 minutes (OAuth 2.1 guidance; default 1800)
```

### 4. Validate Redirect URIs

Redirect URIs are matched exactly at `/oauth/authorize`. Restrict which ones can
register with `allowed_redirect_uri_patterns` (see Client Registration Policy).

### 5. Monitor Failed Authentications

Check logs regularly for suspicious activity:

```bash
grep "\[OAuth\] Error" log/production.log           # every OAuth error response
grep "Refresh-token reuse detected" log/production.log
```

### 6. Implement Rate Limiting

Use rack-attack or similar to prevent brute force attacks:

```ruby
# config/initializers/rack_attack.rb
Rack::Attack.throttle('oauth/token', limit: 20, period: 1.minute) do |req|
  req.ip if req.path == '/oauth/token' && req.post?
end

# Registration is open, so throttle it hard
Rack::Attack.throttle('oauth/register', limit: 5, period: 1.hour) do |req|
  req.ip if req.path == '/oauth/register' && req.post?
end

Rack::Attack.throttle('oauth/other', limit: 60, period: 1.minute) do |req|
  req.ip if req.path.start_with?('/oauth/authorize', '/oauth/revoke', '/oauth/introspect')
end
```

### 7. After Upgrading to 0.6.0

Once `rails g mcp:auth:hash_secrets && rails db:migrate` has run, turn off the
transitional plaintext lookup:

```ruby
config.secret_dual_read = false
```

### 8. Regular Token Cleanup

Run cleanup task daily to remove expired tokens:

```bash
rake mcp_auth:cleanup
```

## Troubleshooting

### Routes Return 404

**Problem**: OAuth endpoints return 404 or redirect to login

**Solution**: Ensure `mount Mcp::Auth::Engine => '/'` is at the very top of `config/routes.rb`, before any other routes (especially catch-all routes or Devise).

```ruby
Rails.application.routes.draw do
  # THIS MUST BE FIRST!
  mount Mcp::Auth::Engine => '/'

  # Then other routes...
  devise_for :users
  # ...
end
```

### "Invalid audience" Errors

**Problem**: Token validation fails with audience mismatch

**Solutions**:
- Check `config.mcp_server_path` matches your actual MCP server mount point
- Verify the `resource` parameter in OAuth requests matches the configured path
- Ensure tokens are being generated with the correct resource URL

```ruby
# config/initializers/mcp_auth.rb
config.mcp_server_path = '/mcp'  # Must match FastMCP mount point

# When generating tokens
resource: 'https://example.com/mcp'  # Must match mcp_server_path
```

### Token Validation Fails

**Problem**: Valid-looking tokens are rejected

**Solutions**:
- Check `oauth_secret` is set correctly and consistently on every server
- Check `mcp_server_url` (or the request host) and `mcp_server_path` match the token's `aud`
- Ensure server clocks are synchronized (JWT exp validation is time-sensitive)
- Verify token hasn't expired (check `exp` claim)
- Check token audience matches your MCP server

```bash
# Decode JWT to inspect claims (without verification)
ruby -rjwt -e "puts JWT.decode('YOUR_TOKEN', nil, false).inspect"
```

### "Missing template" Errors

**Problem**: Missing template errors when the consent screen renders

**Solution**: With `use_custom_consent_view = true` the page renders inside your
`application` layout, so that layout must exist. Otherwise, regenerate the view:

```bash
rails generate mcp:auth:install
```

### PKCE Validation Fails

**Problem**: "PKCE validation failed" error during token exchange

**Solutions**:
- Ensure `code_verifier` exactly matches what was used to generate `code_challenge`
- Verify code_challenge_method is 'S256'
- Check code_verifier is 43-128 characters long
- Ensure proper base64url encoding (no padding)

### Current User Not Found

**Problem**: `undefined method 'current_user'` errors

**Solution**: Ensure your ApplicationController defines these methods:

```ruby
class ApplicationController < ActionController::Base
  def current_user
    # Your authentication logic
  end

  def current_org
    # Your organization logic (optional)
  end
end
```

Or configure different method names:

```ruby
config.current_user_method = :authenticated_user
config.current_org_method = :active_organization
```

## Standards Compliance

MCP Auth implements the following specifications:

- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) - Core authorization framework
- [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) - Dynamic Client Registration Protocol
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - Proof Key for Code Exchange (PKCE)
- [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) - Token Revocation
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) - Token Introspection
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) - Authorization Server Metadata
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) - Resource Indicators for OAuth 2.0
- [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) - OAuth 2.0 Protected Resource Metadata
- [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) - Model Context Protocol Authorization

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/SerhiiBorozenets/mcp-auth.git
cd mcp-auth

# Install dependencies
bundle install

# Run tests
bundle exec rspec

# Check code coverage
open coverage/index.html
```

### Running Tests

```bash
# Run all tests
bundle exec rspec

# Run specific test file
bundle exec rspec spec/services/token_service_spec.rb

# Run with documentation format
bundle exec rspec --format documentation
```

### Code Quality

```bash
# Run RuboCop
bundle exec rubocop

# Auto-correct issues
bundle exec rubocop -a
```

## Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for your changes
4. Ensure all tests pass (`bundle exec rspec`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

Please ensure:
- All tests pass
- Code follows Ruby style guide (run `rubocop`)
- New features include tests and documentation
- Commits are well-described

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Support

- **Issues**: https://github.com/SerhiiBorozenets/mcp-auth/issues
- **Documentation**: https://github.com/SerhiiBorozenets/mcp-auth
- **MCP Specification**: https://modelcontextprotocol.io
- **OAuth 2.1**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Credits

Created by Serhii Borozenets

Built with ❤️ for the Model Context Protocol community.