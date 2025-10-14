# frozen_string_literal: true

module Mcp
  module Auth
    class WellKnownController < ActionController::Base
      skip_before_action :verify_authenticity_token
      before_action :set_cors_headers
      before_action :handle_options_request

      # RFC 9728: OAuth 2.0 Protected Resource Metadata
      def protected_resource
        resource_url = canonical_resource_url

        metadata = {
          resource: resource_url,
          authorization_servers: [authorization_server_url],
          scopes_supported: %w[mcp:read mcp:write],
          bearer_methods_supported: %w[header],
          resource_documentation: "#{request.base_url}/mcp/docs",
          resource_parameter_supported: true, # RFC 8707 support
          authorization_response_iss_parameter_supported: true # OAuth 2.1
        }

        render json: metadata, status: :ok, content_type: 'application/json'
      end

      # RFC 8414: OAuth 2.0 Authorization Server Metadata
      def authorization_server
        metadata = {
          issuer: authorization_server_url,
          authorization_endpoint: "#{authorization_server_url}/oauth/authorize",
          token_endpoint: "#{authorization_server_url}/oauth/token",
          registration_endpoint: "#{authorization_server_url}/oauth/register",
          revocation_endpoint: "#{authorization_server_url}/oauth/revoke",
          introspection_endpoint: "#{authorization_server_url}/oauth/introspect",

          # Supported features
          scopes_supported: %w[mcp:read mcp:write openid profile email],
          response_types_supported: %w[code],
          grant_types_supported: %w[authorization_code refresh_token],
          code_challenge_methods_supported: %w[S256], # PKCE required
          token_endpoint_auth_methods_supported: %w[client_secret_basic client_secret_post none],

          # RFC 8707: Resource Indicators
          resource_parameter_supported: true,

          # OAuth 2.1 features
          authorization_response_iss_parameter_supported: true,
          require_pushed_authorization_requests: false,
          require_signed_request_object: false,

          # Token revocation and introspection
          revocation_endpoint_auth_methods_supported: %w[client_secret_basic client_secret_post none],
          introspection_endpoint_auth_methods_supported: %w[client_secret_basic client_secret_post none]
        }

        render json: metadata, status: :ok, content_type: 'application/json'
      end

      # OpenID Connect Discovery
      def openid_configuration
        metadata = {
          issuer: authorization_server_url,
          authorization_endpoint: "#{authorization_server_url}/oauth/authorize",
          token_endpoint: "#{authorization_server_url}/oauth/token",
          registration_endpoint: "#{authorization_server_url}/oauth/register",
          jwks_uri: "#{authorization_server_url}/.well-known/jwks.json",
          userinfo_endpoint: "#{authorization_server_url}/oauth/userinfo",

          scopes_supported: %w[openid mcp:read mcp:write profile email],
          response_types_supported: %w[code],
          grant_types_supported: %w[authorization_code refresh_token],
          code_challenge_methods_supported: %w[S256],
          token_endpoint_auth_methods_supported: %w[client_secret_basic client_secret_post none],
          subject_types_supported: %w[public],
          id_token_signing_alg_values_supported: %w[HS256]
        }

        render json: metadata, status: :ok, content_type: 'application/json'
      end

      # JWKS endpoint (empty for HMAC)
      def jwks
        keys = { keys: [] }
        render json: keys, status: :ok, content_type: 'application/json'
      end

      private

      def set_cors_headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        response.headers['Content-Type'] = 'application/json; charset=utf-8' unless request.method == 'OPTIONS'
      end

      def handle_options_request
        head :no_content if request.method == 'OPTIONS'
      end

      def canonical_resource_url
        "#{request.scheme}://#{request.host_with_port}/mcp/api"
      end

      def authorization_server_url
        config_url = Mcp::Auth.configuration&.authorization_server_url
        config_url.presence || "#{request.scheme}://#{request.host_with_port}"
      end
    end
  end
end
