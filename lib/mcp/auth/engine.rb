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

      # Load dependencies before initializers
      config.before_initialize do
        require 'mcp/auth/scope_registry'
      end

      initializer "mcp_auth.configure" do
        config.mcp_auth = ActiveSupport::OrderedOptions.new
        config.mcp_auth.authorization_server_url = ENV.fetch('MCP_AUTHORIZATION_SERVER_URL', nil)
        config.mcp_auth.access_token_lifetime = 3600 # 1 hour
        config.mcp_auth.refresh_token_lifetime = 2_592_000 # 30 days
        config.mcp_auth.authorization_code_lifetime = 1800 # 30 minutes
      end

      # Keep OAuth credentials out of the host app's logs. Rails' default filters
      # (:token, :secret, ...) miss the authorization `code` and the PKCE
      # `code_verifier`, which together are enough to redeem a code; the
      # redirect back to the client (`Redirected to ...?code=...`) is filtered too.
      # Anchored regexes, not symbols: Rails matches symbols as SUBSTRINGS across
      # the whole app (and ActiveRecord filter_attributes), so `:code` would also
      # mask `postal_code`, `promo_code`, ...
      OAUTH_FILTER_PARAMETERS = [
        /\Acode\z/, /\Acode_verifier\z/, /\Aclient_secret\z/, /\Arefresh_token\z/,
        /\Aaccess_token\z/, /\Aid_token\z/, /\Atoken\z/
      ].freeze

      initializer 'mcp_auth.filter_parameters' do |app|
        app.config.filter_parameters |= OAUTH_FILTER_PARAMETERS
        app.config.filter_redirect << /[?&]code=/
      end

      # Surface a pending mcp-auth migration at boot so an operator who upgraded
      # the gem without running migrations gets a clear, actionable warning
      # instead of a cryptic runtime error on the first OAuth request. Never
      # raises (missing_columns is fully guarded), so it can't break boot/CI.
      config.after_initialize do
        missing = Mcp::Auth::SchemaGuard.missing_columns
        Rails.logger.warn("[mcp-auth] #{Mcp::Auth::SchemaGuard.guidance(missing)}") if missing.any?

        # Same idea for the signing secret: warn at boot rather than only failing
        # on the first token request (outside dev/test, where it's a hard error).
        unless Rails.env.development? || Rails.env.test?
          problem = Mcp::Auth::Services::TokenService.oauth_secret_problem
          Rails.logger.warn("[mcp-auth] #{problem}") if problem
        end
      rescue StandardError => e
        Rails.logger.debug { "[mcp-auth] boot checks skipped: #{e.class}" }
      end
    end
  end
end