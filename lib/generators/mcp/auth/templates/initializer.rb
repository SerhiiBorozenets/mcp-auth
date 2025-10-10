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
end

# Include controller helpers in ApplicationController
Rails.application.config.to_prepare do
  ApplicationController.include Mcp::Auth::ControllerHelpers
end

