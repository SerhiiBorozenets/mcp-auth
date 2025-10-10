# frozen_string_literal: true

require "rails"
require "jwt"

module Mcp
  module Auth
    class Engine < ::Rails::Engine
      isolate_namespace Mcp::Auth

      config.generators do |g|
        g.test_framework :rspec
        g.fixture_replacement :factory_bot
        g.factory_bot dir: 'spec/factories'
      end

      initializer "mcp_auth.middleware" do |app|
        # Insert middleware after ActionDispatch::Session but before authentication
        app.config.middleware.insert_after ActionDispatch::Session::CookieStore,
                                           Mcp::Auth::Middleware::McpHeadersMiddleware
      end

      initializer "mcp_auth.routes" do
        config.after_initialize do
          Rails.application.routes.append do
            mount Mcp::Auth::Engine => "/"
          end
        end
      end

      initializer "mcp_auth.configure" do
        config.mcp_auth = ActiveSupport::OrderedOptions.new
        config.mcp_auth.oauth_secret = ENV.fetch('MCP_OAUTH_PRIVATE_KEY', nil)
        config.mcp_auth.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)
        config.mcp_auth.access_token_lifetime = 3600 # 1 hour
        config.mcp_auth.refresh_token_lifetime = 2_592_000 # 30 days
        config.mcp_auth.authorization_code_lifetime = 1800 # 30 minutes
      end
    end
  end
end