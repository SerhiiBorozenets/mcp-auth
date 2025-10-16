# frozen_string_literal: true

require 'mcp/auth/version'
require 'mcp/auth/engine'
require 'mcp/auth/services/token_service'
require 'mcp/auth/services/authorization_service'

module Mcp
  module Auth
    class Error < StandardError; end

    class << self
      attr_accessor :configuration
    end

    def self.configure
      self.configuration ||= Configuration.new
      yield(configuration)

      # Also set on Rails.application.config for controllers to access
      Rails.application.config.mcp_auth = configuration if defined?(Rails)
    end

    class Configuration
      attr_accessor :oauth_secret,
                    :authorization_server_url,
                    :access_token_lifetime,
                    :refresh_token_lifetime,
                    :authorization_code_lifetime,
                    :fetch_user_data,
                    :current_user_method,
                    :current_org_method,
                    :consent_view_path,
                    :use_custom_consent_view,
                    :mcp_server_path,
                    :mcp_docs_url

      def initialize
        @oauth_secret = nil
        @authorization_server_url = nil
        @access_token_lifetime = 3600 # 1 hour
        @refresh_token_lifetime = 2_592_000 # 30 days
        @authorization_code_lifetime = 1800 # 30 minutes
        @fetch_user_data = nil
        @current_user_method = :current_user
        @current_org_method = :current_org
        @consent_view_path = 'mcp/auth/consent'
        @use_custom_consent_view = false
        @mcp_server_path = '/mcp/api'  # Default path
        @mcp_docs_url = nil
      end
    end

    # Helper methods for controllers
    module ControllerHelpers
      def mcp_user_id
        request.env['mcp.user_id']
      end

      def mcp_org_id
        request.env['mcp.org_id']
      end

      def mcp_email
        request.env['mcp.email']
      end

      def mcp_token
        request.env['mcp.token']
      end

      def mcp_scope
        request.env['mcp.scope']
      end

      def mcp_api_key
        request.env['mcp.api_key']
      end

      def mcp_authenticated?
        mcp_user_id.present?
      end
    end
  end
end
