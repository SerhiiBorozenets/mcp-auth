# MCP Auth

OAuth 2.1 authorization for Model Context Protocol (MCP) servers in Rails applications.

## Features

- ✅ **OAuth 2.1 Compliant** - Implements the latest OAuth 2.1 draft specification
- ✅ **PKCE Required** - Proof Key for Code Exchange for enhanced security
- ✅ **Dynamic Client Registration** - RFC 7591 support
- ✅ **Resource Indicators** - RFC 8707 for proper token audience binding
- ✅ **Protected Resource Metadata** - RFC 9728 for authorization server discovery
- ✅ **Token Revocation** - RFC 7009 support
- ✅ **Token Introspection** - RFC 7662 support
- ✅ **OpenID Connect** - Basic OpenID Connect Discovery support
- ✅ **Refresh Token Rotation** - Enhanced security for public clients
- ✅ **Built-in Middleware** - Automatic request authentication
- ✅ **Customizable** - Easy to configure for your application's needs

## Installation

Add this line to your application's Gemfile:
```ruby
gem 'mcp-auth'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install mcp-auth
```

## Setup

1. Run the generator to create migrations and initializer:

```bash
rails generate mcp:auth:install
```
2. Mount the Routes
   IMPORTANT: Add this to your config/routes.rb at the very top, before any other routes (especially before catch-all routes or devise):

```ruby
Rails.application.routes.draw do
  # Mount MCP Auth routes FIRST, before any catch-all routes
  mount Mcp::Auth::Engine => '/'
  
  # Then your other routes
  devise_for :users
  root to: 'dashboard#index'
  
  # ... rest of your routes
end
```

⚠️ Why at the top? The gem's routes (like /.well-known/oauth-* and /oauth/*) need to be registered before any catch-all routes or they'll be intercepted by your app's routing.

3. Run the migrations:

```bash
rails db:migrate
```
This creates the following tables:

* `mcp_auth_oauth_clients` - OAuth client registrations
* `mcp_auth_authorization_codes` - Authorization codes with PKCE
* `mcp_auth_access_tokens` - Access tokens
* `mcp_auth_refresh_tokens` - Refresh tokens

4. Configure the initializer at `config/initializers/mcp_auth.rb`:

```ruby
Mcp::Auth.configure do |config|
  # OAuth secret for signing JWTs
  config.oauth_secret = ENV.fetch('MCP_HMAC_SECRET', Rails.application.secret_key_base)
  
  # Authorization server URL (defaults to same as resource server)
  config.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)
  
  # Token lifetimes
  config.access_token_lifetime = 3600 # 1 hour
  config.refresh_token_lifetime = 2_592_000 # 30 days
  config.authorization_code_lifetime = 1800 # 30 minutes

  # Custom user data fetcher - CUSTOMIZE THIS FOR YOUR APP
  config.fetch_user_data = proc do |user_id, org_id|
    user = User.find(user_id)
    {
      email: user.email,
      api_key_id: nil,  # Add your API key logic here if needed
      api_key_secret: nil
    }
  rescue ActiveRecord::RecordNotFound
    { email: 'unknown@example.com', api_key_id: nil, api_key_secret: nil }
  end

  # Methods for getting current user and org
  config.current_user_method = :current_user
  config.current_org_method = :current_org
end
```

5. Ensure Authentication Methods Exist
   Make sure your ApplicationController has these methods:
```ruby
class ApplicationController < ActionController::Base
  # Method to get the currently logged-in user
  def current_user
    # Your logic here (e.g., Devise's current_user)
  end

  # Method to get the current organization (if applicable)
  def current_org
    # Your logic here
  end
end
```
6. Restart Your Server
````bash
spring stop  # Clear spring cache
rails server
````

## Usage

### OAuth Endpoints

MCP Auth automatically provides the following endpoints:

#### Well-Known Endpoints (Discovery)

- `GET /.well-known/oauth-protected-resource` - Protected Resource Metadata (RFC 9728)
- `GET /.well-known/oauth-authorization-server` - Authorization Server Metadata (RFC 8414)
- `GET /.well-known/openid-configuration` - OpenID Connect Discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set

#### OAuth Flow Endpoints

- `GET/POST /oauth/authorize` - Authorization endpoint
- `POST /oauth/approve` - Consent approval endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/register` - Dynamic client registration (RFC 7591)
- `POST /oauth/revoke` - Token revocation (RFC 7009)
- `POST /oauth/introspect` - Token introspection (RFC 7662)
- `GET /oauth/userinfo` - OpenID Connect UserInfo endpoint

### Protecting Your MCP API

The middleware automatically protects all routes under `/mcp/api/`. To access protected resources, clients must include a valid OAuth access token:

```http
GET /mcp/api/resources HTTP/1.1
Host: example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Accessing User Information in Controllers

MCP Auth provides helper methods in your controllers:

```ruby
class MyController < ApplicationController
  def index
    # Check if request is authenticated
    if mcp_authenticated?
      user_id = mcp_user_id
      org_id = mcp_org_id
      email = mcp_email
      scope = mcp_scope
      
      # Your logic here
    else
      render json: { error: 'Unauthorized' }, status: :unauthorized
    end
  end
end
```

Available helper methods:

* `mcp_authenticated?` - Returns true if request has valid token
* `mcp_user_id` - User ID from token
* `mcp_org_id` - Organization ID from token
* `mcp_email` - User email from token
* `mcp_scope` - Token scopes
* `mcp_token` - The access token itself
* `mcp_api_key` - API key if configured

### OAuth 2.1 Authorization Flow

1. **Client Registration** (if using dynamic registration):

```http
POST /oauth/register HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "client_name": "My MCP Client",
  "redirect_uris": ["https://client.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "mcp:read mcp:write"
}
```

2. **Authorization Request** with PKCE:

```
GET /oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://client.example.com/callback&
  scope=mcp:read+mcp:write&
  state=RANDOM_STATE&
  code_challenge=CHALLENGE&
  code_challenge_method=S256&
  resource=https://example.com/mcp/api
```

3. **Token Request**:

```http
POST /oauth/token HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
redirect_uri=https://client.example.com/callback&
code_verifier=VERIFIER&
client_id=CLIENT_ID&
resource=https://example.com/mcp/api
```

4. **Refresh Token**:

```http
POST /oauth/token HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&
client_id=CLIENT_ID
```

### Customizing the Consent Screen
The generator creates a consent view at `app/views/mcp/auth/consent.html.erb`.
If the generator doesn't create the view, copy the template from `CONSENT_VIEW_TEMPLATE.md` in the gem directory.
To customize:

Edit `app/views/mcp/auth/consent.html.erb` to match your branding
Update `config/initializers/mcp_auth.rb`:

````ruby
config.use_custom_consent_view = true
````
The view has access to:

* `@client_name` - Name of the OAuth client
* `@requested_scopes` - Array of scope descriptions
* `@authorization_params` - OAuth parameters to preserve

### Rake Tasks

MCP Auth includes helpful rake tasks:

```bash
# Clean up expired tokens and codes
rake mcp_auth:cleanup

# Show statistics
rake mcp_auth:stats

# Revoke all tokens for a client
rake mcp_auth:revoke_client_tokens[CLIENT_ID]

# Revoke all tokens for a user
rake mcp_auth:revoke_user_tokens[USER_ID]
```

### Scheduled Cleanup

Add this to your scheduler (e.g., `whenever`, `sidekiq-cron`, or `cron`):

```ruby
# Run daily
rake mcp_auth:cleanup
```

## Testing
Test the Installation:

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

In Your Tests

```ruby
# Create tokens directly in tests
user = create(:user)
org = create(:org)

token_data = {
  client_id: 'test-client',
  scope: 'mcp:read mcp:write',
  user_id: user.id,
  org_id: org.id,
  resource: 'https://example.com/mcp/api'
}

access_token = Mcp::Auth::Services::TokenService.generate_access_token(
  token_data,
  base_url: 'https://example.com'
)

# Use in requests
get '/mcp/api/resources', headers: { 'Authorization' => "Bearer #{access_token}" }
```

## Security Considerations

### HTTPS Required
OAuth 2.1 requires HTTPS for all endpoints except localhost. MCP Auth enforces this in production environments.

### PKCE Required
All authorization code flows must use PKCE (Proof Key for Code Exchange) with the S256 method for enhanced security.

### Token Audience Validation
MCP Auth validates that access tokens are intended for your MCP server using RFC 8707 Resource Indicators. This prevents token confusion attacks.

### Refresh Token Rotation
Refresh tokens are automatically rotated when used, following OAuth 2.1 security best practices.

### Short-Lived Access Tokens
Access tokens are short-lived (default 1 hour) to minimize the impact of token theft.

### Environment Variables
Set these environment variables (optional):
```bash
# OAuth secret for JWT signing (recommended in production)
MCP_HMAC_SECRET=your_secure_random_string

# Custom authorization server URL (if different from resource server)
MCP_AUTHORIZATION_SERVER_URL=https://auth.example.com
````

## Troubleshooting

### Routes Not Working
Problem: OAuth endpoints return 404 or redirect to login

Solution: Ensure mount Mcp::Auth::Engine => '/' is at the very top of your config/routes.rb, before any other routes.
````ruby
Rails.application.routes.draw do
  # THIS MUST BE FIRST!
  mount Mcp::Auth::Engine => '/'

  # Then other routes...
  devise_for :users
  # ...
end
````

## Consent Screen Template Missing
Problem: Missing template layouts/mcp_auth error

Solution: Run the generator to create the view:
```bash
rails generate mcp:auth:install
```

## Standards Compliance

MCP Auth implements the following specifications:

- [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) - Core authorization framework
- [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) - Dynamic Client Registration
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - PKCE
- [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) - Token Revocation
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) - Token Introspection
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) - Authorization Server Metadata
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) - Resource Indicators
- [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) - Protected Resource Metadata
- [Model Context Protocol Authorization Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)

## Development

After checking out the repo, run:

```bash
bundle install
```

Run tests with:

```bash
bundle exec rspec
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/SerhiiBorozenets/mcp-auth.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).