# frozen_string_literal: true

Mcp::Auth.configure do |config|
  # ============================================================================
  # OAUTH CONFIGURATION
  # ============================================================================

  # OAuth secret for signing JWTs
  # Should be a secure random string in production (use: rails secret)
  config.oauth_secret = ENV.fetch('MCP_HMAC_SECRET', Rails.application.secret_key_base)

  # Authorization server URL (optional - defaults to same as resource server)
  # Set this if you're using a separate authorization server
  # Example: config.authorization_server_url = 'https://auth.example.com'
  config.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)

  # ============================================================================
  # MCP SERVER CONFIGURATION
  # ============================================================================

  # MCP Server Path - where your MCP server is mounted
  # This MUST match the path where you mount FastMCP or your MCP server
  # Default: '/mcp/api'
  # Examples: '/api/mcp', '/v1/assistant', '/assistant/api'
  config.mcp_server_path = ENV.fetch('MCP_SERVER_PATH', '/mcp/api')

  # MCP Documentation URL - link to your MCP server documentation
  # Can be a full URL (https://docs.example.com/mcp) or a path (/docs/mcp)
  # Default: nil (will auto-generate as {mcp_server_path}/docs)
  # Examples:
  #   config.mcp_docs_url = '/docs/mcp-api'
  #   config.mcp_docs_url = 'https://docs.example.com/mcp-api'
  config.mcp_docs_url = ENV.fetch('MCP_DOCS_URL', nil)

  # ============================================================================
  # TOKEN LIFETIMES (in seconds)
  # ============================================================================

  config.access_token_lifetime = 3600           # 1 hour
  config.refresh_token_lifetime = 2_592_000     # 30 days
  config.authorization_code_lifetime = 1800     # 30 minutes

  # ============================================================================
  # USER DATA FETCHER
  # ============================================================================

  # This proc is called when generating tokens to fetch user-specific data
  # Customize this based on your application's user and organization models
  #
  # Expected return value: Hash with keys:
  #   - :email (String) - User's email address
  #   - :api_key_id (String/Integer, optional) - API key ID if using API keys
  #   - :api_key_secret (String, optional) - API key secret if using API keys
  config.fetch_user_data = proc do |data|
    user = User.find(data[:user_id])

    # Example: If you have API keys per organization user
    # org_user = OrgUser.find_by(user_id: data[:user_id], org_id: data[:org_id])
    # api_key = org_user&.api_key

    {
      email: user.email,
      api_key_id: nil,      # Set to your API key ID if applicable
      api_key_secret: nil   # Set to your API key secret if applicable
    }
  rescue ActiveRecord::RecordNotFound
    { email: 'unknown@example.com', api_key_id: nil, api_key_secret: nil }
  end

  # ============================================================================
  # AUTHENTICATION METHODS
  # ============================================================================

  # Methods used to get current user and organization in your controllers
  # Change these if you use different method names (e.g., authenticated_user)
  config.current_user_method = :current_user
  config.current_org_method = :current_org

  # ============================================================================
  # SCOPE CONFIGURATION
  # ============================================================================

  # MCP Auth starts with NO default scopes. You must register the scopes
  # your application needs. This gives you complete control over permissions.
  #
  # Register scopes that your application needs:
  #
  # Syntax:
  #   config.register_scope 'scope_key',
  #     name: 'Display Name',
  #     description: 'What this scope allows (shown to users)',
  #     required: false  # Set to true if scope is always required
  #
  # IMPORTANT: At least one scope should be registered for OAuth to work properly.
  # If you don't register any scopes, authorization will fail.

  # Common MCP scopes - UNCOMMENT THE ONES YOU NEED:

  # Basic read access - typically required
  config.register_scope 'mcp:read',
                        name: 'Read Access',
                        description: 'Read your data and resources',
                        required: true  # Usually required for MCP to function

  # Write access - allows modifications
  config.register_scope 'mcp:write',
                        name: 'Write Access',
                        description: 'Create and modify data on your behalf',
                        required: false

  # Execute tools and automated actions
  # config.register_scope 'mcp:tools',
  #   name: 'Execute Tools',
  #   description: 'Run tools and perform automated actions in your account'

  # Analytics and reporting
  # config.register_scope 'mcp:analytics',
  #   name: 'Analytics Access',
  #   description: 'View analytics dashboards, charts, and reports'

  # Data export capabilities
  # config.register_scope 'mcp:export',
  #   name: 'Data Export',
  #   description: 'Export data in CSV, PDF, and Excel formats'

  # Administrative access
  # config.register_scope 'mcp:admin',
  #   name: 'Administrative Access',
  #   description: 'Manage settings, users, and perform administrative actions',
  #   required: false

  # Custom application-specific scopes
  # config.register_scope 'mcp:orders',
  #   name: 'Order Management',
  #   description: 'View and manage customer orders'

  # config.register_scope 'mcp:notifications',
  #   name: 'Send Notifications',
  #   description: 'Send notifications and messages on your behalf'

  # ============================================================================
  # SCOPE VALIDATION (OPTIONAL)
  # ============================================================================

  # Validate which scopes users can approve based on their roles/permissions
  # This callback is called for each requested scope during authorization
  #
  # Parameters:
  #   - user: Current user object
  #   - org: Current organization object (may be nil)
  #   - scope: Scope being requested (String)
  #
  # Return:
  #   - true: User can approve this scope
  #   - false: User cannot approve this scope (will be filtered out)
  #
  # Example: Restrict admin scope to admin users only
  # config.validate_scope_for_user = proc do |user, org, scope|
  #   case scope
  #   when 'mcp:admin'
  #     # Only admins can approve admin scope
  #     user.admin? || org&.admins&.include?(user)
  #   when 'mcp:analytics'
  #     # Check if user has analytics permission
  #     user.has_permission?(:view_analytics)
  #   when 'mcp:export'
  #     # Check if organization plan includes export
  #     org&.plan&.includes_export?
  #   else
  #     true  # Allow all other scopes
  #   end
  # end

  # ============================================================================
  # CUSTOM CONSENT VIEW (OPTIONAL)
  # ============================================================================

  # Set to true to use your own consent view instead of the gem's default
  # The view will be at app/views/mcp/auth/consent.html.erb
  config.use_custom_consent_view = false

  # Path to custom consent view (relative to app/views)
  # Only used if use_custom_consent_view is true
  config.consent_view_path = 'mcp/auth/consent'

  # To customize the consent screen:
  # 1. Set use_custom_consent_view = true
  # 2. Copy the default view from the gem or generate it:
  #    rails generate mcp:auth:install
  # 3. Edit app/views/mcp/auth/consent.html.erb
  # 4. The view has access to these instance variables:
  #    - @client_name: Name of the OAuth client requesting access
  #    - @requested_scopes: Array of scope hashes with keys:
  #        * :key - Scope identifier (e.g., 'mcp:read')
  #        * :name - Human-readable name (e.g., 'Read Access')
  #        * :description - What the scope allows
  #        * :required - Whether scope is required (true/false)
  #        * :pre_selected - Whether scope was in the original request
  #    - @authorization_params: Hash of OAuth parameters to preserve
end

# Include controller helpers in ApplicationController
Rails.application.config.to_prepare do
  ApplicationController.include Mcp::Auth::ControllerHelpers
end