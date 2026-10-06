# frozen_string_literal: true

module Mcp
  module Auth
    module Services
      class AuthorizationService
        class << self
          # Generate authorization code with PKCE support. The code is returned to
          # the client in plaintext, but only its digest is persisted (hashed at
          # rest).
          def generate_authorization_code(params, user:, org:)
            code = SecureRandom.hex(32)

            # Use provided scope or default to all registered scopes
            scope = params[:scope].presence || Mcp::Auth::ScopeRegistry.default_scope_string

            Mcp::Auth::AuthorizationCode.create!(
              code: Mcp::Auth::SecretHashing.digest(code),
              client_id: params[:client_id],
              redirect_uri: params[:redirect_uri],
              code_challenge: params[:code_challenge],
              code_challenge_method: params[:code_challenge_method],
              resource: params[:resource],
              scope: scope,
              user: user,
              org: org,
              expires_at: authorization_code_lifetime.seconds.from_now
            )

            Rails.logger.info "[AuthorizationService] Authorization code generated for user #{user.id}"
            code
          rescue ActiveRecord::RecordInvalid => e
            Rails.logger.error "[AuthorizationService] Failed to create authorization code: #{e.message}"
            nil
          end

          # Validate authorization code without consuming it
          def validate_authorization_code(code)
            return nil if code.blank?

            authorization_code = Mcp::Auth::AuthorizationCode.active
                                                             .where(code: Mcp::Auth::SecretHashing.lookup_candidates(code))
                                                             .first
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

          # Consume authorization code (one-time use).
          #
          # OAuth 2.1 §4.1.2: an authorization code MUST be single-use. The
          # delete is done as a single atomic DELETE ... WHERE that reports how
          # many rows it removed, so when two requests race to redeem the same
          # code exactly ONE sees `deleted == 1` and proceeds; the loser sees 0
          # and gets nil. Returns the code's data on success, nil if the code was
          # already consumed (or never existed).
          def consume_authorization_code(code)
            authorization_code = Mcp::Auth::AuthorizationCode
                                 .where(code: Mcp::Auth::SecretHashing.lookup_candidates(code)).first
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

            deleted = Mcp::Auth::AuthorizationCode.where(id: authorization_code.id).delete_all
            return nil unless deleted == 1

            Rails.logger.info '[AuthorizationService] Authorization code consumed'
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

          # Authorization-code TTL in SECONDS (matching every other lifetime in
          # the gem). Read from the single canonical config source so an app that
          # configures via Mcp::Auth.configure and one that relies on defaults
          # agree; 1800s = 30 minutes. (Historically this was read from a second
          # config object and applied as `.minutes`, yielding 30-HOUR codes.)
          def authorization_code_lifetime
            Mcp::Auth.configuration&.authorization_code_lifetime || 1800
          end
        end
      end
    end
  end
end
