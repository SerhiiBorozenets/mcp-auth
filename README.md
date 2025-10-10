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

2. Run the migrations:

```bash
rails db:migrate
```

3. Configure the initializer at `config/initializers/mcp_auth.rb`:

```ruby
Mcp::Auth.configure do |config|
  # OAuth secret for signing JWTs
  config.oauth_secret = ENV.fetch('MCP_OAUTH_PRIVATE_KEY', Rails.application.secret_key_base)
  
  # Authorization server URL (defaults to same as resource server)
  config.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)
  
  # Token lifetimes
  config.access_token_lifetime = 3600 # 1 hour
  config.refresh_token_lifetime = 2_592_000 # 30 days
  config.authorization_code_lifetime = 1800 # 30 minutes
  
  # Custom user data fetcher
  config.fetch_user_data = proc do |user_id, org_id|
    user = User.find(user_id)
    {
      email: user.email,
      api_key_id: nil,
      api_key_secret: nil
    }
  end
end
```

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

## Customization

### Custom User Data

Customize how user data is fetched for tokens:

```ruby
Mcp::Auth.configure do |config|
  config.fetch_user_data = proc do |user_id, org_id|
    user = User.find(user_id)
    org_user = user.org_users.find_by(org_id: org_id)
    
    {
      email: user.email,
      api_key_id: org_user&.api_key&.id,
      api_key_secret: org_user&.api_key&.secret
    }
  end
end
```

### Custom Controller Methods

Specify custom methods for authentication:

```ruby
Mcp::Auth.configure do |config|
  config.current_user_method = :current_user
  config.current_org_method = :current_organization
end
```

## Testing

```ruby
# In your tests, you can create tokens directly:
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

# Use the token in your requests
get '/mcp/api/resources', headers: { 'Authorization' => "Bearer #{access_token}" }
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

Bug reports and pull requests are welcome on GitHub at https://github.com/yourusername/mcp-auth.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).