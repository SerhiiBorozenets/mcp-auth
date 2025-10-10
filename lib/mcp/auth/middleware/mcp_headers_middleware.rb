# frozen_string_literal: true

module Mcp
  module Auth
    module Middleware
      class McpHeadersMiddleware
        def initialize(app)
          @app = app
        end

        def call(env)
          req = Rack::Request.new(env)

          # Only process MCP API requests
          return @app.call(env) unless mcp_api_path?(req.path)

          # Handle CORS preflight
          return cors_preflight_response if req.request_method == 'OPTIONS'

          # Try OAuth Bearer token (RFC 6750)
          if (auth_header = req.get_header('HTTP_AUTHORIZATION'))&.start_with?('Bearer ')
            token = auth_header.split(' ', 2).last
            resource_url = canonical_resource_url(req)

            if (payload = Services::TokenService.validate_access_token(token, resource: resource_url))
              store_auth_data(env, payload, token)
              return @app.call(env)
            end
          end

          # Try API key header (legacy support)
          if (api_key = req.get_header('HTTP_X_API_KEY')).present?
            if validate_api_key(env, api_key)
              return @app.call(env)
            end
          end

          # Return 401 with WWW-Authenticate header (RFC 9728)
          unauthorized_response(req)
        end

        private

        def mcp_api_path?(path)
          path.start_with?('/mcp/api/')
        end

        def canonical_resource_url(req)
          # RFC 8707: Canonical resource URI
          scheme = req.scheme
          host = req.host_with_port
          "#{scheme}://#{host}/mcp/api"
        end

        def store_auth_data(env, payload, token)
          # Store in Rack env for access in controllers
          env['mcp.user_id'] = payload[:sub]
          env['mcp.org_id'] = payload[:org]
          env['mcp.email'] = payload[:email]
          env['mcp.token'] = token
          env['mcp.scope'] = payload[:scope]

          # Store API key if present
          if payload[:api_key_id] && payload[:api_key_secret]
            env['mcp.api_key'] = "#{payload[:api_key_id]} #{payload[:api_key_secret]}"
          end
        end

        def validate_api_key(env, api_key)
          return false if api_key.blank? || api_key.length < 32

          # Store dummy context for API key auth
          env['mcp.user_id'] = 'api_key_user'
          env['mcp.org_id'] = 'api_key_org'
          env['mcp.email'] = 'api@example.com'
          env['mcp.api_key'] = api_key

          true
        end

        def cors_preflight_response
          headers = {
            'Access-Control-Allow-Origin' => '*',
            'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers' => 'Authorization, Content-Type, X-API-Key',
            'Access-Control-Max-Age' => '86400'
          }
          [200, headers, ['']]
        end

        def unauthorized_response(req)
          # RFC 9728: WWW-Authenticate header with resource_metadata
          resource_metadata_url = "#{req.scheme}://#{req.host_with_port}/.well-known/oauth-protected-resource"

          headers = {
            'Content-Type' => 'application/json',
            'Access-Control-Allow-Origin' => '*',
            'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers' => 'Authorization, Content-Type, X-API-Key',
            'WWW-Authenticate' => %(Bearer resource_metadata="#{resource_metadata_url}", scope="mcp:read mcp:write")
          }

          body = {
            error: 'authentication_required',
            error_description: 'Valid OAuth access token required',
            oauth_authorization_url: "#{req.scheme}://#{req.host_with_port}/oauth/authorize",
            resource_metadata_url: resource_metadata_url
          }.to_json

          [401, headers, [body]]
        end
      end
    end
  end
end
