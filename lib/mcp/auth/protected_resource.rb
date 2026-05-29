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

      # Canonical resource identifier for this server (base_url + mcp_server_path),
      # matching the audience minted into access tokens.
      def mcp_resource_identifier
        path = Mcp::Auth.configuration&.mcp_server_path.presence || '/mcp'
        path = "/#{path}" unless path.start_with?('/')
        "#{request.base_url}#{path.chomp('/')}"
      end

      # RFC 9728 §5.1 / MCP authorization spec: a 401 MUST advertise the
      # protected-resource metadata document via WWW-Authenticate so clients can
      # bootstrap the OAuth flow.
      def render_mcp_unauthorized(error, description, status: :unauthorized)
        metadata_url = "#{request.base_url}/.well-known/oauth-protected-resource"
        response.headers['WWW-Authenticate'] =
          %(Bearer error="#{error}", error_description="#{description}", resource_metadata="#{metadata_url}")
        render json: { error: error, error_description: description }, status: status
      end
    end
  end
end
