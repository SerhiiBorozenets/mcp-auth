# frozen_string_literal: true

module Mcp
  module Auth
    module Services
      class AuthorizationService
        class << self
          # Generate authorization code with PKCE support
          def generate_authorization_code(params, user:, org:)
            code = SecureRandom.hex(32)

            authorization_code = Mcp::Auth::AuthorizationCode.create!(
              code: code,
              client_id: params[:client_id],
              redirect_uri: params[:redirect_uri],
              code_challenge: params[:code_challenge],
              code_challenge_method: params[:code_challenge_method],
              resource: params[:resource],
              scope: params[:scope] || 'mcp:read mcp:write',
              user: user,
              org: org,
              expires_at: authorization_code_lifetime.minutes.from_now
            )

            Rails.logger.info "[AuthorizationService] Authorization code generated for user #{user.id}"
            authorization_code.code
          rescue ActiveRecord::RecordInvalid => e
            Rails.logger.error "[AuthorizationService] Failed to create authorization code: #{e.message}"
            nil
          end

          # Validate authorization code without consuming it
          def validate_authorization_code(code)
            return nil if code.blank?

            authorization_code = Mcp::Auth::AuthorizationCode.active.find_by(code: code)
            return nil unless authorization_code

            {
              client_id: authorization_code.client_id,
              redirect_uri: authorization_code.redirect_uri,
              code_challenge: authorization_code.code_challenge,
              code_challenge_method: authorization_code.code_challenge_method,
              resource: authorization_code.resource,
              scope: authorization_code.scope,
              user_id: authorization_code.user_id,
              org_id: authorization_code.org_id,
              created_at: authorization_code.created_at.to_i
            }
          end

          # Consume authorization code (one-time use)
          def consume_authorization_code(code)
            authorization_code = Mcp::Auth::AuthorizationCode.find_by(code: code)
            return nil unless authorization_code

            code_data = {
              client_id: authorization_code.client_id,
              redirect_uri: authorization_code.redirect_uri,
              code_challenge: authorization_code.code_challenge,
              code_challenge_method: authorization_code.code_challenge_method,
              resource: authorization_code.resource,
              scope: authorization_code.scope,
              user_id: authorization_code.user_id,
              org_id: authorization_code.org_id,
              created_at: authorization_code.created_at.to_i
            }

            authorization_code.destroy
            Rails.logger.info "[AuthorizationService] Authorization code consumed"
            code_data
          end

          # Validate PKCE challenge (RFC 7636)
          def validate_pkce?(code_challenge, code_verifier)
            return false if code_verifier.blank? || code_challenge.blank?

            # S256 method: BASE64URL(SHA256(code_verifier))
            computed_challenge = Base64.urlsafe_encode64(
              Digest::SHA256.digest(code_verifier),
              padding: false
            )

            ActiveSupport::SecurityUtils.secure_compare(computed_challenge, code_challenge)
          rescue StandardError => e
            Rails.logger.error "[AuthorizationService] PKCE validation error: #{e.message}"
            false
          end

          private

          def authorization_code_lifetime
            Rails.application.config.mcp_auth.authorization_code_lifetime || 30
          end
        end
      end
    end
  end
end
