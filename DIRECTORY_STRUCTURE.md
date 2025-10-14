# MCP Auth Directory Structure

```
mcp-auth/
│
├── Root Files
│   ├── mcp-auth.gemspec                     # Gem specification
│   ├── Gemfile                              # Development dependencies
│   ├── README.md                            # Main documentation
│   ├── LICENSE.txt                          # MIT License
│   ├── CHANGELOG.md                         # Version history
│   ├── CONTRIBUTING.md                      # Contribution guidelines
│   ├── DIRECTORY_STRUCTURE.md               # This file
│   ├── .gitignore                           # Git ignore rules
│   ├── .rspec                               # RSpec configuration
│   └── .rubocop.yml                         # RuboCop linting rules
│
├── lib/
│   ├── mcp/
│   │   ├── auth.rb                          # Main module loader
│   │   └── auth/
│   │       ├── version.rb                   # Gem version (0.1.0)
│   │       ├── engine.rb                    # Rails engine configuration
│   │       └── services/
│   │           ├── token_service.rb             # JWT generation & validation
│   │           └── authorization_service.rb     # Authorization code & PKCE logic
│   │
│   ├── generators/
│   │   └── mcp/
│   │       └── auth/
│   │           ├── install_generator.rb         # Rails generator
│   │           └── templates/
│   │               ├── README                   # Post-install instructions
│   │               ├── initializer.rb           # Configuration template
│   │               │
│   │               ├── Migration Templates
│   │               ├── create_oauth_clients.rb.erb          # OAuth clients table
│   │               ├── create_authorization_codes.rb.erb    # Auth codes table
│   │               ├── create_access_tokens.rb.erb          # Access tokens table
│   │               ├── create_refresh_tokens.rb.erb         # Refresh tokens table
│   │               │
│   │               └── views/
│   │                   └── consent.html.erb     # OAuth consent screen template
│   │
│   └── tasks/
│       └── mcp_auth_tasks.rake              # Rake tasks (cleanup, stats, revoke)
│
├── app/
│   ├── models/
│   │   └── mcp/
│   │       └── auth/
│   │           ├── oauth_client.rb          # OAuth 2.1 client registrations
│   │           ├── authorization_code.rb    # Short-lived auth codes with PKCE
│   │           ├── access_token.rb          # JWT access tokens
│   │           └── refresh_token.rb         # Long-lived refresh tokens
│   │
│   ├── controllers/
│   │   └── mcp/
│   │       └── auth/
│   │           ├── oauth_controller.rb      # OAuth 2.1 flow endpoints
│   │           │                            # - /oauth/authorize
│   │           │                            # - /oauth/approve
│   │           │                            # - /oauth/token
│   │           │                            # - /oauth/register (RFC 7591)
│   │           │                            # - /oauth/revoke (RFC 7009)
│   │           │                            # - /oauth/introspect (RFC 7662)
│   │           │                            # - /oauth/userinfo (OpenID Connect)
│   │           │
│   │           └── well_known_controller.rb # Discovery endpoints
│   │                                        # - /.well-known/oauth-protected-resource
│   │                                        # - /.well-known/oauth-authorization-server
│   │                                        # - /.well-known/openid-configuration
│   │                                        # - /.well-known/jwks.json
│   │
│   └── views/
│       └── mcp/
│           └── auth/
│               └── consent.html.erb         # OAuth consent screen (self-contained)
│
├── config/
│   └── routes.rb                            # Engine routes configuration
│
└── spec/                                    # Test suite (optional)
├── services/
│   ├── token_service_spec.rb
│   └── authorization_service_spec.rb
├── models/
│   ├── oauth_client_spec.rb
│   ├── authorization_code_spec.rb
│   ├── access_token_spec.rb
│   └── refresh_token_spec.rb
└── factories/
└── oauth_factories.rb
```

## Key Components

### Core Engine (`lib/mcp/auth/`)

**engine.rb**
- Rails engine configuration
- Middleware registration
- Configuration initialization

**version.rb**
- Current version: 0.1.0

### Services (`lib/mcp/auth/services/`)

**token_service.rb**
- JWT access token generation with HS256
- Token validation with audience checking (RFC 8707)
- Refresh token generation and rotation
- Token revocation support

**authorization_service.rb**
- Authorization code generation with PKCE
- Code validation and consumption (one-time use)
- PKCE challenge verification (S256 method)

### Models (`app/models/mcp/auth/`)

**oauth_client.rb**
- OAuth 2.1 client registrations
- Dynamic client registration (RFC 7591)
- Redirect URI validation
- Grant type support

**authorization_code.rb**
- Short-lived codes (30 min default)
- PKCE challenge storage
- Resource indicator support (RFC 8707)
- Auto-cleanup of expired codes

**access_token.rb**
- JWT storage for revocation
- Active/expired scopes
- Resource binding
- 1 hour lifetime (configurable)

**refresh_token.rb**
- 30 day lifetime (configurable)
- Token rotation on use (OAuth 2.1)
- Revocation support

### Controllers (`app/controllers/mcp/auth/`)

**oauth_controller.rb**
- Authorization endpoint with PKCE requirement
- Token endpoint (authorization_code, refresh_token grants)
- Dynamic client registration (RFC 7591)
- Token revocation (RFC 7009)
- Token introspection (RFC 7662)
- UserInfo endpoint (OpenID Connect)
- Consent screen rendering

**well_known_controller.rb**
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)
- OpenID Connect Discovery
- JWKS endpoint

### Views (`app/views/mcp/auth/`)

**consent.html.erb**
- Self-contained HTML with inline CSS
- No layout dependency
- Customizable via generator
- Responsive design

### Generator (`lib/generators/mcp/auth/`)

**install_generator.rb**
- Creates 4 database migrations
- Copies initializer with configuration options
- Copies consent view template
- Shows post-install instructions

**Templates:**
- Migration files for all OAuth tables
- Initializer with comprehensive configuration
- Consent view for customization
- README with setup instructions

### Routes (`config/routes.rb`)

Automatically provides:
- `/.well-known/*` discovery endpoints
- `/oauth/*` authorization endpoints
- CORS support for all endpoints

### Rake Tasks (`lib/tasks/mcp_auth_tasks.rake`)

**Available tasks:**
```bash
rake mcp_auth:cleanup                    # Remove expired tokens
rake mcp_auth:stats                      # Show token statistics
rake mcp_auth:revoke_client_tokens[id]   # Revoke all client tokens
rake mcp_auth:revoke_user_tokens[id]     # Revoke all user tokens