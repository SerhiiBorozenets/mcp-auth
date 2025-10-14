# frozen_string_literal: true

require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)
require "mcp/auth"

module Dummy
  class Application < Rails::Application
    config.load_defaults Rails::VERSION::STRING.to_f

    config.eager_load = false
    config.secret_key_base = "test_secret_key_base"

    # Configure MCP Auth
    Mcp::Auth.configure do |c|
      c.oauth_secret = "test_secret"
      c.access_token_lifetime = 3600
      c.refresh_token_lifetime = 2_592_000
      c.authorization_code_lifetime = 1800

      c.fetch_user_data = proc do |user_id, org_id|
        {
          email: "test@example.com",
          api_key_id: nil,
          api_key_secret: nil
        }
      end
    end
  end
end
