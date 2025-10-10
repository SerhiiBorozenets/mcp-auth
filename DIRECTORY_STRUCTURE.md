# MCP Auth Directory Structure

```
mcp-auth/
├── app/
│   ├── controllers/
│   │   └── mcp/
│   │       └── auth/
│   │           ├── oauth_controller.rb          # OAuth 2.1 endpoints
│   │           └── well_known_controller.rb     # Discovery endpoints
│   ├── models/
│   │   └── mcp/
│   │       └── auth/
│   │           ├── access_token.rb              # Access token model
│   │           ├── authorization_code.rb        # Authorization code model
│   │           ├── oauth_client.rb              # OAuth client model
│   │           └── refresh_token.rb             # Refresh token model
│   └── views/
│       └── mcp/
│           └── auth/
│               └── consent.html.erb             # OAuth consent screen
├── config/
│   └── routes.rb                                 # Engine routes
├── lib/
│   ├── generators/
│   │   └── mcp/
│   │       └── auth/
│   │           ├── install_generator.rb         # Installation generator
│   │           └── templates/
│   │               ├── create_access_tokens.rb.erb
│   │               ├── create_authorization_codes.rb.erb
│   │               ├── create_oauth_clients.rb.erb
│   │               ├── create_refresh_tokens.rb.erb
│   │               ├── initializer.rb           # Initializer template
│   │               └── README                   # Post-install instructions
│   ├── mcp/
│   │   ├── auth/
│   │   │   ├── engine.rb                        # Rails engine
│   │   │   ├── middleware/
│   │   │   │   └── mcp_headers_middleware.rb   # Request authentication
│   │   │   ├── services/
│   │   │   │   ├── authorization_service.rb    # Authorization code logic
│   │   │   │   └── token_service.rb            # Token generation/validation
│   │   │   └── version.rb                       # Gem version
│   │   └── auth.rb                              # Main module file
│   └── tasks/
│       └── mcp_auth_tasks.rake                  # Rake tasks
├── spec/
│   ├── factories/                               # Test factories
│   ├── services/
│   │   └── token_service_spec.rb                # Service tests
│   └── spec_helper.rb                           # RSpec configuration
├── .gitignore                                    # Git ignore rules
├── .rspec                                        # RSpec configuration
├── .rubocop.yml                                  # RuboCop configuration
├── CHANGELOG.md                                  # Version history
├── CONTRIBUTING.md                               # Contribution guidelines
├── Gemfile                                       # Gem dependencies
├── LICENSE.txt                                   # MIT License
├── README.md                                     # Main documentation
└── mcp-auth.gemspec                             # Gem specification
```

## Key Components

### Models (`app/models/mcp/auth/`)
- **OauthClient**: Registered OAuth 2.1 clients with credentials
- **AuthorizationCode**: Short-lived authorization codes with PKCE
- **AccessToken**: JWT access tokens for API access
- **RefreshToken**: Long-lived tokens for obtaining new access tokens

### Controllers (`app/controllers/mcp/auth/`)
- **OauthController**: Handles OAuth 2.1 flow (authorize, token, etc.)
- **WellKnownController**: Provides discovery metadata endpoints

### Services (`lib/mcp/auth/services/`)
- **TokenService**: JWT generation, validation, and management
- **AuthorizationService**: Authorization code and PKCE handling

### Middleware (`lib/mcp/auth/middleware/`)
- **McpHeadersMiddleware**: Authenticates requests to `/mcp/api/*`

### Views (`app/views/mcp/auth/`)
- **consent.html.erb**: User consent screen for OAuth authorization

## Installation Files

The gem provides an install generator that creates:

1. **Migrations**: Four migration files for the database tables
2. **Initializer**: Configuration file at `config/initializers/mcp_auth.rb`
3. **README**: Post-installation instructions

## Configuration

Configuration is done through `Mcp::Auth.configure` block:

```ruby
Mcp::Auth.configure do |config|
  config.oauth_secret = ENV['MCP_OAUTH_PRIVATE_KEY']
  config.access_token_lifetime = 3600
  config.fetch_user_data = proc { |user_id, org_id| ... }
end
```

## Rake Tasks

Located in `lib/tasks/mcp_auth_tasks.rake`:

- `mcp_auth:cleanup` - Remove expired tokens
- `mcp_auth:stats` - Show token statistics
- `mcp_auth:revoke_client_tokens[client_id]` - Revoke client tokens
- `mcp_auth:revoke_user_tokens[user_id]` - Revoke user tokens