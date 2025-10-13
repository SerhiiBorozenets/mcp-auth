# frozen_string_literal: true

Mcp::Auth.configure do |config|
  # OAuth secret for signing JWTs
  # Should be a secure random string in production
  config.oauth_secret = ENV.fetch('MCP_OAUTH_PRIVATE_KEY', Rails.application.secret_key_base)

  # Authorization server URL (defaults to same as resource server)
  config.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)

  # Token lifetimes (in seconds)
  config.access_token_lifetime = 3600 # 1 hour
  config.refresh_token_lifetime = 2_592_000 # 30 days
  config.authorization_code_lifetime = 1800 # 30 minutes

  # Custom user data fetcher
  # This proc should return a hash with :email, :api_key_id, :api_key_secret
  config.fetch_user_data = proc do |user_id, org_id|
    user = User.find(user_id)
    # Customize this based on your application's needs
    {
      email: user.email,
      api_key_id: nil,
      api_key_secret: nil
    }
  rescue ActiveRecord::RecordNotFound
    { email: 'unknown@example.com', api_key_id: nil, api_key_secret: nil }
  end

  # Methods for getting current user and org in controllers
  config.current_user_method = :current_user
  config.current_org_method = :current_org

  # === Custom Consent View ===
  # Set to true to use your own consent view instead of the gem's default
  # The generated view will be at app/views/mcp/auth/consent.html.erb
  # You can customize it to match your app's branding
  config.use_custom_consent_view = false

  # Path to custom consent view (relative to app/views)
  # Only used if use_custom_consent_view is true
  config.consent_view_path = 'mcp/auth/consent'

  # To customize the consent screen:
  # 1. Set use_custom_consent_view = true
  # 2. Edit app/views/mcp/auth/consent.html.erb
  # 3. The view has access to:
  #    - @client_name: Name of the OAuth client
  #    - @requested_scopes: Array of scope descriptions
  #    - @authorization_params: Hash of OAuth parameters
end

# Include controller helpers in ApplicationController
Rails.application.config.to_prepare do
  ApplicationController.include Mcp::Auth::ControllerHelpers
end
