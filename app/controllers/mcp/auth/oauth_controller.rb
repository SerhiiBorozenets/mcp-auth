# frozen_string_literal: true

module Mcp
  module Auth
    class OauthController < ApplicationController
      skip_before_action :verify_authenticity_token, only: %i[token register revoke introspect userinfo]
      before_action :set_cors_headers
      before_action :handle_options_request
      before_action :require_https, only: %i[authorize approve token register revoke introspect userinfo]

      # OAuth 2.1 Authorization endpoint (GET/POST)
      def authorize
        Rails.logger.info "[OAuth] Authorization request for client=#{params[:client_id]} scope=#{params[:scope]}"

        unless valid_authorization_params?
          return render_error('invalid_request', 'Missing or invalid required parameters')
        end

        if mcp_user_signed_in?
          handle_signed_in_user
        else
          redirect_to_login
        end
      end

      # Consent approval endpoint
      def approve
        return redirect_to main_app.new_user_session_path unless mcp_user_signed_in?

        return render_error('invalid_request', 'Missing required parameters') unless valid_authorization_params?

        if params[:approved] == 'true'
          # Get selected scopes from checkboxes
          selected_scopes = Array(params[:scopes]).compact.reject(&:blank?)

          Rails.logger.info "[OAuth] User selected scopes: #{selected_scopes.inspect}"

          # Validate selected scopes
          if selected_scopes.blank?
            Rails.logger.warn '[OAuth] No scopes selected'
            return render_error('invalid_request', 'At least one scope must be selected')
          end

          # Get originally requested scopes
          requested_scopes = params[:scope]&.split || []

          # Get required scopes from the requested list
          required_scopes = get_required_scopes(requested_scopes)

          # Check all required scopes are selected
          missing_required = required_scopes - selected_scopes
          if missing_required.any?
            Rails.logger.warn "[OAuth] Missing required scopes: #{missing_required.join(', ')}"
            return render_error('invalid_request', 'Required scopes must be selected')
          end
          approved_scopes = Mcp::Auth::ScopeRegistry.validate_scopes(selected_scopes)

          # Preserve standard OpenID Connect scopes that were originally requested.
          # They gate identity claims (already governed by the userinfo/id_token
          # endpoints) rather than application resources, so they are not rendered
          # as individual consent checkboxes but must survive the approval step.
          oidc_scopes = requested_scopes & Mcp::Auth::ScopeRegistry::STANDARD_OIDC_SCOPES
          approved_scope_string = (approved_scopes + oidc_scopes).uniq.join(' ')

          # Generate authorization code with ONLY approved scopes
          generate_and_redirect_with_code(approved_scope_string)
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
        Rails.logger.info '[OAuth] Client registration request'

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
      # Requires client authentication; only revokes tokens that belong to the
      # authenticated client (otherwise still returns 200 to avoid leaking which
      # tokens exist — per RFC 7009 §2.2).
      def revoke
        client = authenticate_client
        return render_error('invalid_client', 'Client authentication failed', status: :unauthorized) unless client

        token = params[:token]
        return render_error('invalid_request', 'Token parameter is required') if token.blank?

        revoked = revoke_token_for_client(token, client, hint: params[:token_type_hint])

        # RFC 7009: Always return 200 OK regardless of whether the token was found.
        Rails.logger.info "[OAuth] Token revocation by client=#{client.client_id}: #{revoked ? 'success' : 'not found / not owned'}"
        head :ok
      end

      # RFC 7662: Token Introspection
      # Requires client authentication. Tokens not owned by the authenticated
      # client are reported as `{active: false}` to prevent token-scanning.
      def introspect
        client = authenticate_client
        return render_error('invalid_client', 'Client authentication failed', status: :unauthorized) unless client

        token = params[:token]
        return render json: { active: false }, content_type: 'application/json' if token.blank?

        response = introspect_token_for_client(token, client)
        render json: response, content_type: 'application/json'
      end

      # OpenID Connect UserInfo Endpoint
      def userinfo
        auth_header = request.headers['Authorization']

        return render json: { error: 'invalid_token' }, status: :unauthorized unless auth_header&.start_with?('Bearer ')

        token = auth_header.split(' ', 2).last
        payload = Services::TokenService.validate_access_token(token)

        return render json: { error: 'invalid_token' }, status: :unauthorized unless payload

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
          params[:code_challenge_method] == 'S256' &&
          registered_client_with_valid_redirect?
      end

      # OAuth 2.1 / RFC 6749 §3.1.2.3: the authorization endpoint MUST reject any
      # redirect_uri that is not pre-registered for the client. This is the gate
      # that prevents authorization-code interception via open redirect, so it is
      # validated BEFORE the code is ever issued — and on failure we render an
      # error instead of redirecting (we must never redirect to an unverified URI).
      def registered_client_with_valid_redirect?
        client = oauth_client
        unless client
          Rails.logger.warn "[OAuth] Unknown client_id: #{params[:client_id]}"
          return false
        end

        return true if client.valid_redirect_uri?(params[:redirect_uri])

        Rails.logger.warn "[OAuth] Unregistered redirect_uri for client=#{params[:client_id]}: #{params[:redirect_uri]}"
        false
      end

      def oauth_client
        return @oauth_client if defined?(@oauth_client)

        @oauth_client = Mcp::Auth::OauthClient.find_by(client_id: params[:client_id])
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

      def generate_and_redirect_with_code(approved_scope = nil)
        # Use approved scopes if provided, otherwise use requested scopes,
        # otherwise use all registered scopes
        final_scope = approved_scope.presence ||
                      params[:scope].presence ||
                      Mcp::Auth::ScopeRegistry.default_scope_string

        Rails.logger.info "[OAuth] Generating auth code with scope: #{final_scope}"

        # Create a new params hash with the final scope
        auth_params = params.to_unsafe_h.merge(scope: final_scope)

        # Pass the params with approved scope to authorization service
        code = Services::AuthorizationService.generate_authorization_code(
          auth_params,
          user: mcp_current_user,
          org: current_org
        )

        return render_error('server_error', 'Failed to generate authorization code') unless code

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
        # RFC 9207: iss MUST be included in authorization responses, including errors.
        query_params[:iss] = authorization_server_url

        redirect_uri.query = URI.encode_www_form(query_params)
        redirect_to redirect_uri.to_s, allow_other_host: true
      end

      # === Token Grants ===

      def handle_authorization_code_grant
        code_data = Services::AuthorizationService.validate_authorization_code(params[:code])

        return render_error('invalid_grant', 'Authorization code is invalid or expired') unless code_data

        # RFC 6749 §4.1.3: the code MUST be bound to the client it was issued to.
        # The requesting client identifies itself via HTTP Basic auth (confidential
        # clients) or the client_id parameter (public clients using PKCE).
        unless requesting_client_id.present? && requesting_client_id == code_data[:client_id]
          return render_error('invalid_grant', 'Authorization code was issued to a different client')
        end

        # Validate PKCE
        unless Services::AuthorizationService.validate_pkce?(code_data[:code_challenge], params[:code_verifier])
          return render_error('invalid_grant', 'PKCE validation failed')
        end

        # Validate redirect URI
        unless code_data[:redirect_uri] == params[:redirect_uri]
          return render_error('invalid_grant', 'Redirect URI mismatch')
        end

        # Use the APPROVED scope from the authorization code, not the original request
        Rails.logger.info "[OAuth] Token generation using scope from auth code: #{code_data[:scope]}"

        # Consume the authorization code FIRST (one-time use). Doing this before
        # token generation guarantees a replayed code can never yield a second
        # set of tokens even if two requests race.
        Services::AuthorizationService.consume_authorization_code(params[:code])

        # Generate tokens with the APPROVED scope from authorization code
        token_data = code_data.merge(resource: code_data[:resource] || params[:resource])
        token_response = Services::TokenService.generate_token_response(
          token_data, # This includes the approved :scope from authorization code
          base_url: request.base_url
        )

        render json: token_response, content_type: 'application/json'
      rescue StandardError => e
        Rails.logger.error "[OAuth] Token generation failed: #{e.message}"
        render_error('server_error', 'Failed to issue tokens', status: :internal_server_error)
      end

      def handle_refresh_token_grant
        token_data = Services::TokenService.validate_refresh_token(params[:refresh_token])

        return render_error('invalid_grant', 'Refresh token is invalid or expired') unless token_data

        # RFC 6749 §6: a client may request a NARROWER scope on refresh, never a
        # wider one. Silently dropping unknown/extra scopes preserves least privilege.
        token_data[:scope] = narrow_scope(token_data[:scope], params[:scope]) if params[:scope].present?

        # Include resource parameter if provided
        token_data[:resource] = params[:resource] if params[:resource]

        # Rotate refresh token (OAuth 2.1 requirement) BEFORE issuing the new one
        # so a replayed refresh token cannot mint a second token family.
        Services::TokenService.revoke_refresh_token(params[:refresh_token])

        # Generate new tokens
        token_response = Services::TokenService.generate_token_response(
          token_data,
          base_url: request.base_url
        )

        render json: token_response, content_type: 'application/json'
      rescue StandardError => e
        Rails.logger.error "[OAuth] Token refresh failed: #{e.message}"
        render_error('server_error', 'Failed to issue tokens', status: :internal_server_error)
      end

      # Intersection of the originally granted scope and a requested subset.
      def narrow_scope(granted_scope, requested_scope)
        granted = granted_scope.to_s.split
        requested = requested_scope.to_s.split
        (granted & requested).join(' ')
      end

      # client_id of the party making a token request: HTTP Basic auth wins for
      # confidential clients, otherwise the public client_id parameter.
      def requesting_client_id
        basic_id, = extract_client_credentials_from_basic
        basic_id.presence || params[:client_id]
      end

      # === Client Registration ===

      def build_client_registration
        {
          redirect_uris: extract_redirect_uris,
          grant_types: params[:grant_types] || %w[authorization_code refresh_token],
          response_types: params[:response_types] || %w[code],
          scope: params[:scope] || Mcp::Auth::ScopeRegistry.default_scope_string,
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

      # === Client Authentication (RFC 6749 §2.3, used by revoke + introspect) ===

      # Accepts client credentials from either HTTP Basic auth or form params.
      # Returns the OauthClient instance on success, nil on failure.
      def authenticate_client
        client_id, client_secret = extract_client_credentials
        return nil if client_id.blank? || client_secret.blank?

        client = Mcp::Auth::OauthClient.find_by(client_id: client_id)
        return nil unless client
        return nil unless ActiveSupport::SecurityUtils.secure_compare(client.client_secret.to_s, client_secret.to_s)

        client
      end

      def extract_client_credentials
        basic_id, basic_secret = extract_client_credentials_from_basic
        return [basic_id, basic_secret] if basic_id.present?

        [params[:client_id], params[:client_secret]]
      end

      # Returns [client_id, client_secret] from an HTTP Basic Authorization
      # header, or [nil, nil] when the header is absent/not Basic.
      def extract_client_credentials_from_basic
        auth = request.authorization
        return [nil, nil] unless auth&.start_with?('Basic ')

        decoded = Base64.decode64(auth.split(' ', 2).last)
        id, secret = decoded.split(':', 2)
        [id, secret]
      end

      # RFC 7009: revoke token only if it belongs to the requesting client.
      # token_type_hint is a hint, not a constraint — try both regardless.
      def revoke_token_for_client(token, client, hint: nil)
        if hint == 'refresh_token'
          revoke_refresh_for_client(token, client) || revoke_access_for_client(token, client)
        else
          revoke_access_for_client(token, client) || revoke_refresh_for_client(token, client)
        end
      end

      def revoke_access_for_client(token, client)
        access_token = Mcp::Auth::AccessToken.find_by(token: token, client_id: client.client_id)
        return false unless access_token

        access_token.destroy
        true
      end

      def revoke_refresh_for_client(token, client)
        refresh_token = Mcp::Auth::RefreshToken.find_by(token: token, client_id: client.client_id)
        return false unless refresh_token

        refresh_token.destroy
        true
      end

      # RFC 7662: only describe tokens owned by the authenticated client.
      def introspect_token_for_client(token, client)
        payload = Services::TokenService.validate_access_token(token)
        if payload && payload[:client_id] == client.client_id
          build_access_token_introspection(payload)
        else
          refresh_data = Services::TokenService.validate_refresh_token(token)
          if refresh_data && refresh_data[:client_id] == client.client_id
            build_refresh_token_introspection(refresh_data)
          else
            { active: false }
          end
        end
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

      # === Consent Screen - ONLY ONE DEFINITION ===

      def show_consent_screen
        @client_name = get_client_name
        @requested_scopes = parse_and_validate_scopes
        @authorization_params = params.to_unsafe_h.slice(
          :response_type, :client_id, :redirect_uri, :scope,
          :state, :code_challenge, :code_challenge_method, :resource
        )

        if use_custom_consent_view?
          render Rails.application.config.mcp_auth.consent_view_path, layout: 'application'
        else
          render 'mcp/auth/consent', layout: false
        end
      end

      def use_custom_consent_view?
        config = Rails.application.config.mcp_auth
        config.use_custom_consent_view &&
          template_exists?(config.consent_view_path)
      rescue StandardError
        false
      end

      def template_exists?(path)
        lookup_context.exists?(path, [], false)
      rescue StandardError
        false
      end

      def get_client_name
        client = Mcp::Auth::OauthClient.find_by_client_id(params[:client_id])
        client&.client_name || params[:client_name] || params[:client_id] || 'Unknown Application'
      end

      def parse_and_validate_scopes
        # Get requested scopes, or default to all registered scopes
        scope_string = params[:scope].presence || Mcp::Auth::ScopeRegistry.default_scope_string
        requested = scope_string.split

        # Get ALL available scopes (what the gem owner registered)
        all_available = Mcp::Auth::ScopeRegistry.available_scopes.keys

        # Filter by user permissions if configured
        if Mcp::Auth.configuration.validate_scope_for_user
          all_available = all_available.select do |scope|
            Mcp::Auth.configuration.validate_scope_for_user.call(
              mcp_current_user,
              current_org,
              scope
            )
          end
        end

        # Format all available scopes for display
        # Mark as pre-selected if they were in the original request
        all_scopes = Mcp::Auth::ScopeRegistry.format_for_display(all_available)

        # Add a flag to indicate if scope was originally requested
        all_scopes.map do |scope_data|
          scope_data.merge(
            pre_selected: requested.include?(scope_data[:key])
          )
        end
      end

      # Get required scopes from requested scopes list
      def get_required_scopes(requested_scopes)
        validated = Mcp::Auth::ScopeRegistry.validate_scopes(requested_scopes)

        validated.select do |scope|
          metadata = Mcp::Auth::ScopeRegistry.scope_metadata(scope)
          metadata[:required]
        end
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
        return if request.ssl? || request.local? || Rails.env.local?

        render_error('invalid_request', 'HTTPS required')
      end

      def authorization_server_url
        config_url = Rails.application.config.mcp_auth.authorization_server_url
        config_url.presence || "#{request.scheme}://#{request.host_with_port}"
      end

      # === Error Handling ===

      def render_error(error, description, status: :bad_request)
        error_response = {
          error: error,
          error_description: description
        }

        Rails.logger.error "[OAuth] Error: #{error_response.inspect}"
        render json: error_response, status: status, content_type: 'application/json'
      end

      # Resolve the signed-in user via the configured `current_user_method`
      # (defaults to :current_user). Accepts either a symbol naming a method on
      # the host ApplicationController or a proc evaluated in this context.
      def mcp_current_user
        method_name = Mcp::Auth.configuration&.current_user_method || :current_user
        return instance_exec(&method_name) if method_name.respond_to?(:call)

        send(method_name) if respond_to?(method_name, true)
      rescue NoMethodError
        nil
      end

      def mcp_user_signed_in?
        mcp_current_user.present?
      end

      def current_org
        # If current_org_method is nil in config, always return nil
        return nil if Mcp::Auth.configuration.current_org_method.nil?

        # Otherwise, call the configured method
        method_name = Mcp::Auth.configuration.current_org_method

        # If it's a proc, execute it in this controller's context
        return instance_exec(&method_name) if method_name.respond_to?(:call)

        # If it's a symbol/string, call it (from parent ApplicationController)
        super if defined?(super)
      rescue NoMethodError
        # Method doesn't exist in parent, return nil
        nil
      end
    end
  end
end
