# frozen_string_literal: true

module Mcp
  module Auth
    # Resource-server side of the MCP authorization spec. Include this in the
    # controller that serves your MCP endpoint to validate the incoming Bearer
    # token and expose the authenticated principal via Mcp::Auth::ControllerHelpers
    # (mcp_user_id, mcp_scope, ...).
    #
    #   class McpController < ApplicationController
    #     include Mcp::Auth::ProtectedResource
    #     before_action :authenticate_mcp_token!
    #     before_action -> { require_mcp_scope!('mcp:read') }, only: :show
    #   end
    #
    # On a missing/invalid/expired token it answers 401 with the RFC 9728
    # WWW-Authenticate header so MCP clients can discover the authorization
    # server from the protected-resource metadata.
    module ProtectedResource
      extend ActiveSupport::Concern
      include Mcp::Auth::ControllerHelpers

      # Build the RFC 9728 §5.1 / MCP-spec `WWW-Authenticate` header value for a
      # 401 from a protected MCP resource. Exposed as a plain function (no request
      # object needed) so it can be used from a Rack middleware guarding /mcp, not
      # only from this controller concern — a 401 without this header leaves
      # spec-compliant MCP clients (e.g. MCP Inspector) unable to discover the
      # protected-resource metadata and refresh/re-authorize.
      #
      #   headers['WWW-Authenticate'] =
      #     Mcp::Auth::ProtectedResource.www_authenticate(request.base_url)
      def self.www_authenticate(base_url, error: 'invalid_token',
                                description: 'The access token is missing, invalid, or expired')
        metadata_url = "#{base_url}/.well-known/oauth-protected-resource"
        %(Bearer error="#{error}", error_description="#{description}", resource_metadata="#{metadata_url}")
      end

      # Validates the Bearer access token (signature, expiry, revocation status,
      # and — when a resource is configured — the RFC 8707 audience). On success
      # the decoded claims are stashed in request.env for ControllerHelpers and
      # the payload is returned; on failure it renders 401 and halts the action.
      def authenticate_mcp_token!
        token = mcp_bearer_token
        payload = token && Services::TokenService.validate_access_token(token, resource: mcp_resource_identifier)

        unless payload
          render_mcp_unauthorized('invalid_token', 'The access token is missing, invalid, or expired')
          return false
        end

        request.env['mcp.user_id'] = payload[:sub]
        request.env['mcp.org_id']  = payload[:org]
        request.env['mcp.email']   = payload[:email]
        request.env['mcp.token']   = token
        request.env['mcp.scope']   = payload[:scope]
        request.env['mcp.api_key'] = payload[:api_key_id]
        payload
      end

      # Enforce that the validated token carries every given scope. Renders 403
      # insufficient_scope and returns false when any is missing.
      def require_mcp_scope!(*required)
        granted = mcp_scope.to_s.split
        missing = required.map(&:to_s) - granted
        return true if missing.empty?

        render_mcp_unauthorized(
          'insufficient_scope',
          "Missing required scope: #{missing.join(' ')}",
          status: :forbidden
        )
        false
      end

      private

      def mcp_bearer_token
        header = request.authorization || request.headers['Authorization']
        return nil unless header&.start_with?('Bearer ')

        header.split(' ', 2).last.presence
      end

      # Canonical resource identifier for this server (server origin +
      # mcp_server_path), matching the audience minted into access tokens. Prefer
      # the configured authorization_server_url so the audience check is pinned to
      # a trusted origin rather than a (possibly forged) request Host.
      def mcp_resource_identifier
        origin = Mcp::Auth.configuration&.authorization_server_url.presence || request.base_url
        path = Mcp::Auth.configuration&.mcp_server_path.presence || '/mcp'
        path = "/#{path}" unless path.start_with?('/')
        "#{origin}#{path.chomp('/')}"
      end

      # RFC 9728 §5.1 / MCP authorization spec: a 401 MUST advertise the
      # protected-resource metadata document via WWW-Authenticate so clients can
      # bootstrap the OAuth flow.
      def render_mcp_unauthorized(error, description, status: :unauthorized)
        response.headers['WWW-Authenticate'] =
          Mcp::Auth::ProtectedResource.www_authenticate(request.base_url, error: error, description: description)
        render json: { error: error, error_description: description }, status: status
      end
    end
  end
end
