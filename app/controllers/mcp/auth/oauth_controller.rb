# frozen_string_literal: true

module Mcp
  module Auth
    class OauthController < ApplicationController
      skip_before_action :verify_authenticity_token, only: %i[token register revoke introspect userinfo]
      before_action :set_cors_headers
      before_action :handle_options_request
      before_action :require_https, only: %i[authorize token]

      # OAuth 2.1 Authorization endpoint (GET/POST)
      def authorize
        Rails.logger.info "[OAuth] Authorization request: #{params.inspect}"

        unless valid_authorization_params?
          return render_error('invalid_request', 'Missing or invalid required parameters')
        end

        if user_signed_in?
          handle_signed_in_user
        else
          redirect_to_login
        end
      end

      # Consent approval endpoint
      def approve
        unless user_signed_in?
          return redirect_to new_user_session_path
        end

        unless valid_authorization_params?
          return render_error('invalid_request', 'Missing required parameters')
        end

        if params[:approved] == 'true'
          generate_and_redirect_with_code
        else
          redirect_with_error('access_denied', 'User denied the request')
        end
      end

      # OAuth 2.1 Token endpoint
      def token
        case params[:grant_type]
        when 'authorization_code'
          handle_authorization_code_grant
        when 'refresh_token'
          handle_refresh_token_grant
        else
          render_error('unsupported_grant_type', 'Grant type not supported')
        end
      end

      # RFC 7591: Dynamic Client Registration
      def register
        Rails.logger.info "[OAuth] Client registration request"

        begin
          client_data = build_client_registration
          oauth_client = Mcp::Auth::OauthClient.create!(client_data)

          Rails.logger.info "[OAuth] Client registered: #{oauth_client.client_id}"
          render json: format_client_response(oauth_client), content_type: 'application/json'
        rescue ActiveRecord::RecordInvalid => e
          render_error('invalid_client_metadata', e.message)
        rescue ArgumentError => e
          render_error('invalid_request', e.message)
        rescue StandardError => e
          Rails.logger.error "[OAuth] Registration error: #{e.message}"
          render_error('server_error', 'An unexpected error occurred')
        end
      end

      # RFC 7009: Token Revocation
      def revoke
        token = params[:token]

        if token.blank?
          return render_error('invalid_request', 'Token parameter is required')
        end

        # Try refresh token first
        revoked = Services::TokenService.revoke_refresh_token(token)

        # Try access token if not found
        unless revoked
          access_token = Mcp::Auth::AccessToken.find_by(token: token)
          if access_token
            access_token.destroy
            revoked = true
          end
        end

        # RFC 7009: Always return 200 OK
        Rails.logger.info "[OAuth] Token revocation: #{revoked ? 'success' : 'not found'}"
        head :ok
      end

      # RFC 7662: Token Introspection
      def introspect
        token = params[:token]

        if token.blank?
          return render json: { active: false }, content_type: 'application/json'
        end

        # Try as JWT access token
        payload = Services::TokenService.validate_access_token(token)

        response = if payload
                     build_access_token_introspection(payload)
                   else
                     # Try as refresh token
                     refresh_data = Services::TokenService.validate_refresh_token(token)
                     refresh_data ? build_refresh_token_introspection(refresh_data) : { active: false }
                   end

        render json: response, content_type: 'application/json'
      end

      # OpenID Connect UserInfo
      def userinfo
        auth_header = request.headers['Authorization']

        unless auth_header&.start_with?('Bearer ')
          return render json: { error: 'invalid_token' }, status: :unauthorized
        end

        token = auth_header.split(' ', 2).last
        payload = Services::TokenService.validate_access_token(token)

        unless payload
          return render json: { error: 'invalid_token' }, status: :unauthorized
        end

        user_info = {
          sub: payload[:sub],
          email: payload[:email],
          email_verified: true,
          name: payload[:email],
          preferred_username: payload[:email]
        }
        user_info[:org] = payload[:org] if payload[:org]

        render json: user_info, content_type: 'application/json'
      end

      private

      # === Validation ===

      def valid_authorization_params?
        params[:response_type] == 'code' &&
          params[:client_id].present? &&
          params[:redirect_uri].present? &&
          params[:code_challenge].present? &&
          params[:code_challenge_method] == 'S256'
      end

      # === Authorization Flow ===

      def handle_signed_in_user
        if params[:approved] == 'true'
          generate_and_redirect_with_code
        else
          show_consent_screen
        end
      end

      def redirect_to_login
        session[:oauth_params] = request.query_parameters
        redirect_to main_app.new_user_session_path
      end

      def generate_and_redirect_with_code
        code = Services::AuthorizationService.generate_authorization_code(
          params,
          user: current_user,
          org: current_org
        )

        unless code
          return render_error('server_error', 'Failed to generate authorization code')
        end

        redirect_with_code(code)
      end

      def redirect_with_code(code)
        redirect_uri = URI.parse(params[:redirect_uri])
        query_params = { code: code }
        query_params[:state] = params[:state] if params[:state]
        query_params[:iss] = authorization_server_url # OAuth 2.1

        redirect_uri.query = URI.encode_www_form(query_params)
        redirect_to redirect_uri.to_s, allow_other_host: true
      end

      def redirect_with_error(error, description)
        redirect_uri = URI.parse(params[:redirect_uri])
        query_params = { error: error, error_description: description }
        query_params[:state] = params[:state] if params[:state]

        redirect_uri.query = URI.encode_www_form(query_params)
        redirect_to redirect_uri.to_s, allow_other_host: true
      end

      # === Token Grants ===

      def handle_authorization_code_grant
        code_data = Services::AuthorizationService.validate_authorization_code(params[:code])

        unless code_data
          return render_error('invalid_grant', 'Authorization code is invalid or expired')
        end

        # Validate PKCE
        unless Services::AuthorizationService.validate_pkce?(code_data[:code_challenge], params[:code_verifier])
          return render_error('invalid_grant', 'PKCE validation failed')
        end

        # Validate redirect URI
        unless code_data[:redirect_uri] == params[:redirect_uri]
          return render_error('invalid_grant', 'Redirect URI mismatch')
        end

        # Generate tokens with resource from authorization request
        token_data = code_data.merge(resource: code_data[:resource] || params[:resource])
        token_response = Services::TokenService.generate_token_response(
          token_data,
          base_url: request.base_url
        )

        # Consume authorization code (one-time use)
        Services::AuthorizationService.consume_authorization_code(params[:code])

        render json: token_response, content_type: 'application/json'
      end

      def handle_refresh_token_grant
        token_data = Services::TokenService.validate_refresh_token(params[:refresh_token])

        unless token_data
          return render_error('invalid_grant', 'Refresh token is invalid or expired')
        end

        # Include resource parameter if provided
        token_data[:resource] = params[:resource] if params[:resource]

        # Generate new tokens
        token_response = Services::TokenService.generate_token_response(
          token_data,
          base_url: request.base_url
        )

        # Rotate refresh token (OAuth 2.1 requirement)
        Services::TokenService.revoke_refresh_token(params[:refresh_token])

        render json: token_response, content_type: 'application/json'
      end

      # === Client Registration ===

      def build_client_registration
        {
          redirect_uris: extract_redirect_uris,
          grant_types: params[:grant_types] || %w[authorization_code refresh_token],
          response_types: params[:response_types] || %w[code],
          scope: params[:scope] || 'mcp:read mcp:write',
          client_name: params[:client_name] || 'MCP Client',
          client_uri: params[:client_uri]
        }
      end

      def extract_redirect_uris
        uris = params[:redirect_uris] || []
        Array(uris).uniq
      end

      def format_client_response(client)
        {
          client_id: client.client_id,
          client_secret: client.client_secret,
          client_id_issued_at: client.created_at.to_i,
          client_secret_expires_at: 0,
          redirect_uris: client.redirect_uris,
          grant_types: client.grant_types,
          response_types: client.response_types,
          scope: client.scope,
          token_endpoint_auth_method: 'client_secret_basic',
          client_name: client.client_name,
          client_uri: client.client_uri
        }.compact
      end

      # === Token Introspection ===

      def build_access_token_introspection(payload)
        {
          active: true,
          client_id: payload[:client_id] || 'unknown',
          username: payload[:email],
          scope: payload[:scope],
          exp: payload[:exp],
          iat: payload[:iat],
          sub: payload[:sub],
          aud: payload[:aud],
          iss: payload[:iss],
          token_type: 'Bearer'
        }
      end

      def build_refresh_token_introspection(data)
        {
          active: true,
          client_id: data[:client_id],
          scope: data[:scope],
          token_type: 'refresh_token'
        }
      end

      # === Consent Screen ===

      def show_consent_screen
        @client_name = get_client_name
        @requested_scopes = parse_scopes
        @authorization_params = params.to_unsafe_h.slice(
          :response_type, :client_id, :redirect_uri, :scope,
          :state, :code_challenge, :code_challenge_method, :resource
        )

        render 'mcp/auth/consent', layout: 'mcp_auth'
      end

      def get_client_name
        client = Mcp::Auth::OauthClient.find_by_client_id(params[:client_id])
        client&.client_name || params[:client_name] || params[:client_id] || 'Unknown Application'
      end

      def parse_scopes
        scope_string = params[:scope] || 'mcp:read mcp:write'
        scopes = scope_string.split

        scope_descriptions = {
          'mcp:read' => 'Read access to your data and reports',
          'mcp:write' => 'Create and modify data on your behalf',
          'openid' => 'Access your basic profile information',
          'profile' => 'Access your profile information',
          'email' => 'Access your email address'
        }

        scopes.map { |scope| scope_descriptions[scope] || scope }
      end

      # === Headers & Security ===

      def set_cors_headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
      end

      def handle_options_request
        head :no_content if request.method == 'OPTIONS'
      end

      def require_https
        return if request.ssl? || request.local? || Rails.env.development?

        render_error('invalid_request', 'HTTPS required')
      end

      def authorization_server_url
        config_url = Rails.application.config.mcp_auth.authorization_server_url
        config_url.presence || "#{request.scheme}://#{request.host_with_port}"
      end

      # === Error Handling ===

      def render_error(error, description)
        error_response = {
          error: error,
          error_description: description
        }

        Rails.logger.error "[OAuth] Error: #{error_response.inspect}"
        render json: error_response, status: :bad_request, content_type: 'application/json'
      end
    end
  end
end
