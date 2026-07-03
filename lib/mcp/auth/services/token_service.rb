# frozen_string_literal: true

module Mcp
  module Auth
    module Services
      class TokenService
        # Clock-skew tolerance (seconds) applied to exp/nbf verification so a
        # small difference between the signer's and verifier's clocks doesn't
        # spuriously reject an otherwise-valid token.
        CLOCK_SKEW_LEEWAY_SECONDS = 30

        class << self
          # Validate access token with optional resource verification (RFC 8707).
          # Supports HS256, RS256, and ES256 — algorithm comes from configuration.
          def validate_access_token(token, resource: nil)
            return nil if token.blank?

            begin
              payload = decode_with_known_keys(token)
              return nil unless payload

              # Check expiration manually to ensure proper handling
              return nil if payload['exp'] && (payload['exp'] <= Time.current.to_i)

              # Token-use separation: an id_token is signed with the same key/alg
              # as an access token, so cryptographically it would otherwise verify
              # here. Reject anything not minted as an access token. (Legacy tokens
              # without the claim are still accepted; the DB row check below is the
              # second gate — id_tokens are never stored.)
              token_use = payload['token_use']
              return nil unless token_use.nil? || token_use == 'access'

              # Revocation check (RFC 7009): a JWT remains cryptographically valid
              # until it expires, so a stored-and-still-present row is what makes
              # `revoke` actually take effect. Without this, destroyed tokens would
              # keep validating until natural expiry. The row is keyed by the
              # token's digest (tokens are hashed at rest).
              candidates = SecretHashing.lookup_candidates(token)
              return nil unless Mcp::Auth::AccessToken.active.where(token: candidates).exists?

              # Validate audience if a resource was provided (RFC 8707). `aud` is a
              # required claim (enforced at decode), so a token lacking it never
              # reaches here — no silent skip on a missing audience.
              if resource && !audience_matches?(payload['aud'], resource)
                Rails.logger.warn "[TokenService] Token audience mismatch: expected #{resource}, got #{payload['aud']}"
                return nil
              end

              payload.symbolize_keys
            rescue JWT::DecodeError, JWT::ExpiredSignature => e
              Rails.logger.debug { "[TokenService] Token validation failed: #{e.message}" }
              nil
            rescue StandardError => e
              Rails.logger.error "[TokenService] Token validation error: #{e.message}"
              nil
            end
          end

          # Decode against every key we currently trust. For HS256 that is the
          # single shared secret; for RS256/ES256 it is the active public key plus
          # any additional public keys configured for rotation, so tokens signed
          # with the previous key keep validating across a key roll.
          def decode_with_known_keys(token)
            last_error = nil
            verification_keys.each do |key|
              return JWT.decode(token, key, true, decode_options).first
            rescue JWT::DecodeError => e
              last_error = e
            end
            raise last_error if last_error

            nil
          end

          # Decode options shared across verification keys. The algorithm is
          # pinned to a single value (blocks `alg:none` and RS↔HS confusion);
          # `exp`/`nbf` are verified with a small clock-skew leeway; and the
          # core claims are required so a token missing `iss`/`aud`/`sub`/`exp`
          # is rejected outright rather than silently passing later checks.
          def decode_options
            {
              algorithm: signing_algorithm,
              verify_expiration: true,
              verify_not_before: true,
              leeway: CLOCK_SKEW_LEEWAY_SECONDS,
              required_claims: %w[iss aud sub exp]
            }
          end

          # Generate JWT access token with proper audience binding
          def generate_access_token(data, base_url:)
            user_data = fetch_user_data(data)

            # RFC 8707: Use provided resource or default to the configured MCP
            # endpoint. The default MUST mirror the canonical resource published in
            # the protected-resource metadata, which is built from mcp_server_path —
            # otherwise audience validation breaks for any non-default path.
            audience = normalize_resource_uri(data[:resource].presence || default_audience(base_url))

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
              # Marks this JWT as an access token so it can't be replayed as an
              # id_token (or vice versa); verified in validate_access_token.
              token_use: 'access',
              # Only a non-sensitive API key *identifier* is embedded. A bearer
              # JWT is decodable by anyone holding it (and is stored at rest), so
              # the matching secret MUST NOT be placed in the token — the resource
              # server resolves the secret server-side from this id when needed.
              api_key_id: user_data[:api_key_id],
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

          # Generate refresh token. The opaque value is returned to the client in
          # plaintext, but only its digest is persisted (hashed at rest). Tokens
          # descend within a `family_id`: the first issuance starts a new family;
          # a rotation reuses the presented token's family so a later replay can
          # be detected as reuse.
          def generate_refresh_token(data)
            refresh_token = SecureRandom.hex(32)

            # Use provided expires_at or default
            expires_at = data[:expires_at] || refresh_token_lifetime.seconds.from_now

            begin
              Mcp::Auth::RefreshToken.create!(
                token: SecretHashing.digest(refresh_token),
                client_id: data[:client_id],
                scope: data[:scope],
                user_id: data[:user_id],
                org_id: data[:org_id],
                family_id: data[:family_id].presence || SecureRandom.uuid,
                expires_at: expires_at
              )

              Rails.logger.info "[TokenService] Refresh token created for user #{data[:user_id]}"
              refresh_token
            rescue ActiveRecord::RecordInvalid => e
              Rails.logger.error "[TokenService] Failed to create refresh token: #{e.message}"
              nil
            end
          end

          # Look up the refresh-token record for a presented value in ANY state
          # (active, expired, or revoked) so the caller can implement reuse
          # detection. Honors dual-read (digest or legacy plaintext).
          def find_refresh_token(raw)
            return nil if raw.blank?

            Mcp::Auth::RefreshToken.where(token: SecretHashing.lookup_candidates(raw)).first
          end

          # Atomically consume a refresh token by flipping revoked_at from NULL.
          # Returns true only for the request that actually performed the flip, so
          # concurrent redemptions of the same token can't both rotate.
          def rotate_refresh_token(record)
            Mcp::Auth::RefreshToken
              .where(id: record.id, revoked_at: nil)
              .update_all(revoked_at: Time.current) == 1
          end

          # Revoke every still-live token in a family (used on reuse detection).
          def revoke_refresh_family(family_id)
            return 0 if family_id.blank?

            Mcp::Auth::RefreshToken
              .where(family_id: family_id, revoked_at: nil)
              .update_all(revoked_at: Time.current)
          end

          # Validate refresh token
          def validate_refresh_token(refresh_token)
            return nil if refresh_token.blank?

            token_record = Mcp::Auth::RefreshToken.where(token: SecretHashing.lookup_candidates(refresh_token)).first
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

          # Revoke a refresh token (RFC 7009) atomically. Deletes in a single
          # DELETE ... WHERE and reports whether a row was actually removed, so a
          # caller can use the boolean as a rotation gate: when two requests race
          # to redeem the same refresh token, exactly one sees `true` and may
          # issue a new token family; the loser sees `false`.
          def revoke_refresh_token(refresh_token)
            return false if refresh_token.blank?

            deleted = Mcp::Auth::RefreshToken.where(token: SecretHashing.lookup_candidates(refresh_token)).delete_all
            Rails.logger.info '[TokenService] Refresh token revoked' if deleted.positive?
            deleted.positive?
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

            # OpenID Connect: only issue an id_token when the `openid` scope was granted.
            if openid_scope?(data[:scope])
              id_token = generate_id_token(data, base_url: base_url)
              response[:id_token] = id_token if id_token
            end

            response
          rescue StandardError => e
            Rails.logger.error "[TokenService] Failed to generate token response: #{e.message}"
            raise
          end

          # OpenID Connect ID Token. Audience is the client_id (not the resource),
          # per the OIDC core spec. Only the claims permitted by the granted
          # profile/email scopes are included.
          def generate_id_token(data, base_url:)
            return nil if data[:client_id].blank?

            user_data = fetch_user_data(data)
            scopes = data[:scope].to_s.split

            payload = {
              iss: base_url,
              sub: data[:user_id].to_s,
              aud: data[:client_id],
              token_use: 'id', # distinguishes this from an access token
              iat: Time.current.to_i,
              exp: Time.current.to_i + token_lifetime
            }
            if scopes.include?('email')
              payload[:email] = user_data[:email]
              payload[:email_verified] = true
            end
            payload[:name] = user_data[:email] if scopes.include?('profile')

            jwt_headers = signing_kid ? { kid: signing_kid } : {}
            JWT.encode(payload, signing_key, signing_algorithm, jwt_headers)
          rescue StandardError => e
            Rails.logger.error "[TokenService] Failed to generate id_token: #{e.message}"
            nil
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

          # All public JWKs to publish at the JWKS endpoint: the active key plus
          # any additional rotation keys. During a key roll the previous key stays
          # listed so already-issued tokens keep verifying. Empty for HS256.
          def signing_jwks_export
            return [] unless asymmetric_signing?

            keys = [signing_jwk_export]
            additional_public_keys.each do |pkey|
              additional_jwk = JWT::JWK.new(pkey)
              exported = additional_jwk.export
              exported[:alg] = signing_algorithm
              exported[:use] = 'sig'
              keys << exported
            end
            keys.compact
          end

          # Clears memoized key material. Call after rotating signing keys at
          # runtime (otherwise the previously loaded keys stay cached for the
          # life of the process).
          def reset_signing_keys!
            @cached_private_key = nil
            @cached_public_key = nil
            @jwk = nil
          end

          # RFC 8707 §2 / MCP authorization spec: an authorization server MUST
          # only honor resource indicators that name a resource it actually
          # serves. A blank resource defaults to the canonical resource, so it is
          # allowed; otherwise the request is accepted only when the requested
          # resource matches this server's canonical resource (normalized, never
          # a substring match). This stops a malicious client from minting tokens
          # whose `aud` is some other — possibly attacker-controlled — resource.
          def resource_allowed?(resource, canonical_resource)
            return true if resource.blank?

            audience_matches?(canonical_resource, resource)
          end

          private

          def asymmetric_signing?
            Mcp::Auth.configuration&.asymmetric_signing? || false
          end

          # Canonical resource URI used as the default token audience, derived from
          # the configured mcp_server_path so it matches the published metadata.
          def default_audience(base_url)
            path = Mcp::Auth.configuration&.mcp_server_path.presence || '/mcp'
            path = "/#{path}" unless path.start_with?('/')
            path = path.chomp('/')
            "#{base_url}#{path}"
          end

          def openid_scope?(scope)
            scope.to_s.split.include?('openid')
          end

          # Public keys accepted for verification beyond the active one (rotation).
          def additional_public_keys
            Array(Mcp::Auth.configuration&.token_signing_additional_public_keys).filter_map do |raw|
              next raw if raw.is_a?(OpenSSL::PKey::PKey)

              OpenSSL::PKey.read(raw) if raw.present?
            end
          end

          def signing_algorithm
            Mcp::Auth.configuration&.token_signing_algorithm || 'HS256'
          end

          # Key used to SIGN outgoing JWTs (HMAC secret for HS256, private key
          # for RS256/ES256).
          def signing_key
            asymmetric_signing? ? cached_private_key : oauth_secret
          end

          # Keys used to VERIFY incoming JWTs. HS256 verifies with the single
          # shared secret; RS256/ES256 verifies against the active public key plus
          # any configured rotation keys.
          def verification_keys
            return [oauth_secret] unless asymmetric_signing?

            [cached_public_key, *additional_public_keys].compact
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

          # HMAC secret for HS256 signing. A dedicated secret MUST be configured:
          # silently reusing Rails' secret_key_base (which also signs cookies and
          # every MessageVerifier) breaks key separation. In production a missing
          # secret is a hard error; in dev/test we fall back so the gem still boots.
          def oauth_secret
            secret = Mcp::Auth.configuration&.oauth_secret
            return secret if secret.present?

            if defined?(Rails) && Rails.env.production?
              raise Mcp::Auth::Error,
                    'Mcp::Auth.configuration.oauth_secret must be set — refusing to sign tokens with ' \
                    'Rails.application.secret_key_base in production (key separation).'
            end

            Rails.application.secret_key_base
          end

          def token_lifetime
            Mcp::Auth.configuration&.access_token_lifetime || 3600
          end

          def refresh_token_lifetime
            Mcp::Auth.configuration&.refresh_token_lifetime || 2_592_000
          end

          # RFC 8707: Normalize resource URI (remove trailing slash, lowercase scheme/host)
          def normalize_resource_uri(uri)
            parsed = URI.parse(uri.to_s)

            # A resource indicator must be an absolute URI with scheme + host.
            # Anything else (relative path, mailto, garbage) is returned verbatim
            # so callers compare it as an opaque string rather than crashing.
            return uri.to_s if parsed.scheme.nil? || parsed.host.nil?

            normalized = "#{parsed.scheme.downcase}://#{parsed.host.downcase}"
            normalized += ":#{parsed.port}" if parsed.port && !default_port?(parsed)
            normalized += parsed.path.chomp('/') if parsed.path.present? && parsed.path != '/'
            normalized
          rescue URI::InvalidURIError, ArgumentError => e
            Rails.logger.warn "[TokenService] Invalid resource URI: #{uri} - #{e.message}"
            uri.to_s
          end

          def default_port?(parsed_uri)
            (parsed_uri.scheme == 'http' && parsed_uri.port == 80) ||
              (parsed_uri.scheme == 'https' && parsed_uri.port == 443)
          end

          # RFC 8707: Check if token audience matches requested resource.
          # `aud` may be a single value or an array (RFC 7519 §4.1.3). Comparison
          # is on the normalized canonical URI — NOT a string prefix, which would
          # let `https://api.example.com.evil.com` match `https://api.example.com`.
          def audience_matches?(token_audience, resource)
            normalized_resource = normalize_resource_uri(resource)

            Array(token_audience).any? do |aud|
              normalize_resource_uri(aud) == normalized_resource
            end
          end

          def store_access_token(token, data, audience)
            # Use provided expires_at or default
            expires_at = data[:expires_at] || token_lifetime.seconds.from_now

            Mcp::Auth::AccessToken.create!(
              token: SecretHashing.digest(token),
              client_id: data[:client_id],
              resource: audience,
              scope: data[:scope],
              user_id: data[:user_id],
              org_id: data[:org_id],
              expires_at: expires_at
            )
            Rails.logger.info "[TokenService] Access token stored for user #{data[:user_id]}"
          rescue ActiveRecord::RecordInvalid => e
            # Validation now depends on the stored row existing, so a token we
            # failed to persist would be useless AND unrevocable. Fail loudly
            # instead of handing the client a dead bearer token.
            Rails.logger.error "[TokenService] Failed to store access token: #{e.message}"
            raise
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
