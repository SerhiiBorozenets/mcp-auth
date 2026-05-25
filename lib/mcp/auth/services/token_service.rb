# frozen_string_literal: true

module Mcp
  module Auth
    module Services
      class TokenService
        class << self
          # Validate access token with optional resource verification (RFC 8707).
          # Supports HS256, RS256, and ES256 — algorithm comes from configuration.
          def validate_access_token(token, resource: nil)
            return nil if token.blank?

            begin
              payload = JWT.decode(token, verification_key, true, { algorithm: signing_algorithm }).first

              # Check expiration manually to ensure proper handling
              if payload['exp']
                return nil if payload['exp'] <= Time.current.to_i
              end

              # Validate audience if resource provided (RFC 8707 compliance)
              if resource && payload['aud'].present?
                unless audience_matches?(payload['aud'], resource)
                  Rails.logger.warn "[TokenService] Token audience mismatch: expected #{resource}, got #{payload['aud']}"
                  return nil
                end
              end

              payload.symbolize_keys
            rescue JWT::DecodeError, JWT::ExpiredSignature => e
              Rails.logger.debug "[TokenService] Token validation failed: #{e.message}"
              nil
            rescue StandardError => e
              Rails.logger.error "[TokenService] Token validation error: #{e.message}"
              nil
            end
          end

          # Generate JWT access token with proper audience binding
          def generate_access_token(data, base_url:)
            user_data = fetch_user_data(data)

            # RFC 8707: Use provided resource or default to MCP API endpoint
            audience = normalize_resource_uri(data[:resource].presence || "#{base_url}/mcp")

            # Calculate expiration time
            exp_time = data[:expires_at] ? data[:expires_at].to_i : (Time.current.to_i + token_lifetime)

            payload = {
              iss: base_url,
              aud: audience,
              sub: data[:user_id].to_s,
              org: data[:org_id]&.to_s,
              client_id: data[:client_id],
              email: user_data[:email],
              scope: data[:scope],
              api_key_id: user_data[:api_key_id],
              api_key_secret: user_data[:api_key_secret],
              iat: Time.current.to_i,
              exp: exp_time
            }

            jwt_headers = signing_kid ? { kid: signing_kid } : {}
            token = JWT.encode(payload, signing_key, signing_algorithm, jwt_headers)

            # Store token in database for revocation support
            store_access_token(token, data, audience)

            token
          rescue StandardError => e
            Rails.logger.error "[TokenService] Failed to generate access token: #{e.message}"
            raise
          end

          # Generate refresh token
          def generate_refresh_token(data)
            refresh_token = SecureRandom.hex(32)

            # Use provided expires_at or default
            expires_at = data[:expires_at] || refresh_token_lifetime.seconds.from_now

            begin
              Mcp::Auth::RefreshToken.create!(
                token: refresh_token,
                client_id: data[:client_id],
                scope: data[:scope],
                user_id: data[:user_id],
                org_id: data[:org_id],
                expires_at: expires_at
              )

              Rails.logger.info "[TokenService] Refresh token created for user #{data[:user_id]}"
              refresh_token
            rescue ActiveRecord::RecordInvalid => e
              Rails.logger.error "[TokenService] Failed to create refresh token: #{e.message}"
              nil
            end
          end

          # Validate refresh token
          def validate_refresh_token(refresh_token)
            return nil if refresh_token.blank?

            token_record = Mcp::Auth::RefreshToken.find_by(token: refresh_token)
            return nil unless token_record

            # Check if token is expired
            return nil if token_record.expires_at < Time.current

            Rails.logger.info "[TokenService] Refresh token validated for user #{token_record.user_id}"
            {
              client_id: token_record.client_id,
              scope: token_record.scope,
              user_id: token_record.user_id,
              org_id: token_record.org_id
            }
          end

          # Revoke refresh token (RFC 7009)
          def revoke_refresh_token(refresh_token)
            return false if refresh_token.blank?

            token_record = Mcp::Auth::RefreshToken.find_by(token: refresh_token)
            return false unless token_record

            token_record.destroy
            Rails.logger.info "[TokenService] Refresh token revoked"
            true
          end

          # Generate complete token response
          def generate_token_response(data, base_url:)
            access_token = generate_access_token(data, base_url: base_url)
            refresh_token = generate_refresh_token(data)

            response = {
              access_token: access_token,
              token_type: 'Bearer',
              expires_in: token_lifetime,
              scope: data[:scope]
            }

            response[:refresh_token] = refresh_token if refresh_token
            response
          rescue StandardError => e
            Rails.logger.error "[TokenService] Failed to generate token response: #{e.message}"
            raise
          end

          # Public key used to sign new JWTs. Configured via Mcp::Auth.configure;
          # built lazily so apps that stay on HS256 don't have to set anything.
          def signing_public_key
            return nil unless asymmetric_signing?

            cached_public_key
          end

          # JWK identifier for the current signing key — included as `kid` in
          # JWT headers and the JWKS entry. Falls back to JWT::JWK's
          # auto-derived thumbprint when no explicit kid is configured.
          def signing_kid
            return nil unless asymmetric_signing?

            Mcp::Auth.configuration&.token_signing_kid.presence || jwk.kid
          end

          # JWK for the active public key, suitable for the JWKS endpoint.
          # Returns nil for HS256 (HMAC keys are never published).
          def signing_jwk_export
            return nil unless asymmetric_signing?

            exported = jwk.export
            exported[:kid] = signing_kid
            exported[:alg] = signing_algorithm
            exported[:use] = 'sig'
            exported
          end

          private

          def asymmetric_signing?
            Mcp::Auth.configuration&.asymmetric_signing? || false
          end

          def signing_algorithm
            Mcp::Auth.configuration&.token_signing_algorithm || 'HS256'
          end

          # Key used to SIGN outgoing JWTs (HMAC secret for HS256, private key
          # for RS256/ES256).
          def signing_key
            asymmetric_signing? ? cached_private_key : oauth_secret
          end

          # Key used to VERIFY incoming JWTs (HMAC secret for HS256, public key
          # for RS256/ES256). For asymmetric algorithms callers may eventually
          # want per-token key lookup via the JWT `kid` header, but for now we
          # only have one active key so a single value is fine.
          def verification_key
            asymmetric_signing? ? cached_public_key : oauth_secret
          end

          def cached_private_key
            @cached_private_key ||= load_private_key
          end

          def cached_public_key
            @cached_public_key ||= load_public_key
          end

          def jwk
            @jwk ||= JWT::JWK.new(cached_public_key)
          end

          def load_private_key
            raw = Mcp::Auth.configuration&.token_signing_private_key
            raise 'token_signing_private_key is not configured' if raw.blank?

            raw.is_a?(OpenSSL::PKey::PKey) ? raw : OpenSSL::PKey.read(raw)
          end

          def load_public_key
            raw = Mcp::Auth.configuration&.token_signing_public_key
            if raw.present?
              return raw if raw.is_a?(OpenSSL::PKey::PKey)

              return OpenSSL::PKey.read(raw)
            end

            # Derive from the private key when an explicit public key isn't given.
            private_key = cached_private_key
            case private_key
            when OpenSSL::PKey::RSA then private_key.public_key
            when OpenSSL::PKey::EC  then ec_public_key_from(private_key)
            else
              raise "Unsupported private key type for #{signing_algorithm}: #{private_key.class}"
            end
          end

          # OpenSSL::PKey::EC#public_key returns the bare point, not a usable
          # PKey instance. Build a public-only EC key so JWT::JWK can export it.
          def ec_public_key_from(private_key)
            pub = OpenSSL::PKey::EC.new(private_key.group)
            pub.public_key = private_key.public_key
            pub
          end

          def oauth_secret
            secret = Mcp::Auth.configuration&.oauth_secret
            secret.presence || Rails.application.secret_key_base
          end

          def token_lifetime
            Mcp::Auth.configuration&.access_token_lifetime || 3600
          end

          def refresh_token_lifetime
            Mcp::Auth.configuration&.refresh_token_lifetime || 2_592_000
          end

          # RFC 8707: Normalize resource URI (remove trailing slash, lowercase scheme/host)
          def normalize_resource_uri(uri)
            parsed = URI.parse(uri)
            normalized = "#{parsed.scheme.downcase}://#{parsed.host.downcase}"
            normalized += ":#{parsed.port}" if parsed.port && !default_port?(parsed)
            normalized += parsed.path.chomp('/') if parsed.path.present? && parsed.path != '/'
            normalized
          rescue URI::InvalidURIError => e
            Rails.logger.warn "[TokenService] Invalid resource URI: #{uri} - #{e.message}"
            uri
          end

          def default_port?(parsed_uri)
            (parsed_uri.scheme == 'http' && parsed_uri.port == 80) ||
              (parsed_uri.scheme == 'https' && parsed_uri.port == 443)
          end

          # RFC 8707: Check if token audience matches requested resource
          def audience_matches?(token_audience, resource)
            normalized_audience = normalize_resource_uri(token_audience)
            normalized_resource = normalize_resource_uri(resource)

            # Exact match or audience is a prefix of resource
            normalized_audience == normalized_resource ||
              normalized_resource.start_with?(normalized_audience)
          end

          def store_access_token(token, data, audience)
            # Use provided expires_at or default
            expires_at = data[:expires_at] || token_lifetime.seconds.from_now

            Mcp::Auth::AccessToken.create!(
              token: token,
              client_id: data[:client_id],
              resource: audience,
              scope: data[:scope],
              user_id: data[:user_id],
              org_id: data[:org_id],
              expires_at: expires_at
            )
            Rails.logger.info "[TokenService] Access token stored for user #{data[:user_id]}"
          rescue ActiveRecord::RecordInvalid => e
            Rails.logger.error "[TokenService] Failed to store access token: #{e.message}"
          end

          def fetch_user_data(data)
            if Mcp::Auth.configuration&.fetch_user_data
              Mcp::Auth.configuration.fetch_user_data.call(data)
            else
              default_fetch_user_data(data[:user_id])
            end
          end

          def default_fetch_user_data(user_id)
            user = User.find(user_id)
            {
              email: user.email,
              api_key_id: nil,
              api_key_secret: nil
            }
          rescue ActiveRecord::RecordNotFound
            { email: 'unknown@example.com', api_key_id: nil, api_key_secret: nil }
          end
        end
      end
    end
  end
end
