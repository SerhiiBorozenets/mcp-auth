# frozen_string_literal: true

module Mcp
  module Auth
    class OauthClient < ActiveRecord::Base
      self.table_name = 'mcp_auth_oauth_clients'
      self.primary_key = 'client_id'

      # Set defaults BEFORE validation
      before_validation :set_defaults, on: :create
      before_validation :sanitize_client_name
      # Hash the secret at rest just before persisting (covers both the
      # auto-generated secret and one a caller sets explicitly).
      before_save :hash_client_secret_at_rest

      # The grant/response types this authorization server actually implements.
      # Dynamic registration is rejected for anything outside these sets so a
      # client cannot register metadata the server can't honor (RFC 7591 §2).
      SUPPORTED_GRANT_TYPES = %w[authorization_code refresh_token].freeze
      SUPPORTED_RESPONSE_TYPES = %w[code].freeze

      # Token-endpoint authentication methods (RFC 7591 / RFC 8414). PUBLIC_AUTH_METHOD
      # (`none`) is a public client (PKCE only, no client authentication); the
      # others are CONFIDENTIAL clients that MUST present a valid client_secret.
      # Defaults to `none` so existing/registered clients keep working — a client
      # opts into confidential auth explicitly at registration.
      PUBLIC_AUTH_METHOD = 'none'
      TOKEN_ENDPOINT_AUTH_METHODS = [PUBLIC_AUTH_METHOD, 'client_secret_basic', 'client_secret_post'].freeze

      # Schemes that must never receive an authorization code: they execute
      # script or read local content rather than reaching a client
      # (e.g. `javascript://%0aalert(1)` would otherwise pass the `://` check).
      FORBIDDEN_REDIRECT_SCHEMES = %w[javascript data vbscript file about blob].freeze

      LOOPBACK_HOSTS = %w[localhost 127.0.0.1 [::1] ::1].freeze
      MAX_CLIENT_NAME_LENGTH = 100

      validates :client_id, presence: true, uniqueness: true
      validates :client_secret, presence: true
      validates :token_endpoint_auth_method, inclusion: { in: TOKEN_ENDPOINT_AUTH_METHODS }
      validate :validate_redirect_uris
      validate :validate_grant_and_response_types
      validate :validate_redirect_uri_policy
      validate :validate_scope_known
      validate :validate_client_uri

      serialize :redirect_uris, coder: JSON
      serialize :grant_types, coder: JSON
      serialize :response_types, coder: JSON

      has_many :authorization_codes,
               class_name: 'Mcp::Auth::AuthorizationCode',
               foreign_key: :client_id,
               primary_key: :client_id,
               dependent: :destroy

      has_many :access_tokens,
               class_name: 'Mcp::Auth::AccessToken',
               foreign_key: :client_id,
               primary_key: :client_id,
               dependent: :destroy

      has_many :refresh_tokens,
               class_name: 'Mcp::Auth::RefreshToken',
               foreign_key: :client_id,
               primary_key: :client_id,
               dependent: :destroy

      # The generated plaintext secret, available only on the in-memory instance
      # right after creation (never persisted). The registration response returns
      # this once; only its digest is stored.
      attr_reader :plaintext_secret

      def self.find_by_client_id(client_id)
        find_by(client_id: client_id)
      end

      def valid_redirect_uri?(uri)
        redirect_uris&.include?(uri)
      end

      def supports_grant_type?(grant_type)
        grant_types&.include?(grant_type)
      end

      # Constant-time verification of a presented client_secret against the stored
      # digest (secrets are hashed at rest).
      def authenticate_secret(presented)
        Mcp::Auth::SecretHashing.match?(client_secret, presented)
      end

      # Confidential clients MUST authenticate at the token endpoint; public
      # clients (`none`) rely on PKCE.
      def confidential?
        token_endpoint_auth_method.to_s != PUBLIC_AUTH_METHOD
      end

      private

      def set_defaults
        self.client_id ||= SecureRandom.uuid
        self.client_secret = SecureRandom.hex(32) if client_secret.blank?
        self.grant_types ||= %w[authorization_code refresh_token]
        self.response_types ||= %w[code]
        self.scope ||= Mcp::Auth::ScopeRegistry.default_scope_string
        self.token_endpoint_auth_method = PUBLIC_AUTH_METHOD if token_endpoint_auth_method.blank?
      end

      # Digest the secret before it is written. The plaintext (generated or
      # caller-supplied) is captured on the in-memory instance first so the
      # registration response can return it exactly once.
      def hash_client_secret_at_rest
        return if client_secret.blank? || Mcp::Auth::SecretHashing.hashed?(client_secret)

        @plaintext_secret ||= client_secret
        self.client_secret = Mcp::Auth::SecretHashing.digest(client_secret)
      end

      # RFC 7591 / RFC 8252: a client using the authorization_code grant must
      # register at least one redirect URI, and each must be an absolute URI.
      # We reject scheme-only values (e.g. `javascript:`/`data:`) that would be
      # XSS-redirect vectors, while still allowing http(s) and native app schemes.
      def validate_redirect_uris
        uris = Array(redirect_uris)
        if uris.empty?
          if Array(grant_types).include?('authorization_code')
            errors.add(:redirect_uris, 'must include at least one redirect URI')
          end
          return
        end

        uris.each do |uri|
          errors.add(:redirect_uris, "contains an invalid redirect URI: #{uri}") unless valid_redirect_uri_format?(uri)
        end
      end

      def validate_grant_and_response_types
        (Array(grant_types) - SUPPORTED_GRANT_TYPES).each do |gt|
          errors.add(:grant_types, "contains an unsupported grant type: #{gt}")
        end
        (Array(response_types) - SUPPORTED_RESPONSE_TYPES).each do |rt|
          errors.add(:response_types, "contains an unsupported response type: #{rt}")
        end
      end

      # The consent page shows client_name, which is attacker-chosen at open
      # registration: strip control/format characters (bidi overrides, zero-width)
      # and cap the length so it can't impersonate or spoof layout.
      def sanitize_client_name
        return if client_name.blank?

        self.client_name = client_name.to_s.gsub(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/, ' ').squish.truncate(MAX_CLIENT_NAME_LENGTH)
      end

      # OAuth 2.1 / RFC 9700 §4.1.1: redirect URIs must be https, or http only on
      # a loopback host; and, when configured, must match the allowlist.
      # Runs for EVERY registered redirect URI, whatever the grant types: a client
      # registered without authorization_code must not be able to slip an
      # off-policy URI past this check. (/oauth/authorize also refuses clients
      # that didn't register the authorization_code grant.)
      def validate_redirect_uri_policy
        Array(redirect_uris).each do |uri|
          next unless valid_redirect_uri_format?(uri) # already reported

          parsed = URI.parse(uri.to_s)
          loopback = loopback_redirect?(parsed)
          if parsed.is_a?(URI::HTTP) && !parsed.is_a?(URI::HTTPS) && !loopback
            errors.add(:redirect_uris, "must use https (http is only allowed for loopback): #{uri}")
          elsif loopback && config_value(:allow_loopback_redirects, true) == false
            errors.add(:redirect_uris, "loopback redirect URIs are not allowed: #{uri}")
          elsif !loopback && !redirect_uri_allowlisted?(uri)
            errors.add(:redirect_uris, "is not an allowed redirect URI: #{uri}")
          end
        end
      end

      def loopback_redirect?(parsed)
        parsed.is_a?(URI::HTTP) && LOOPBACK_HOSTS.include?(parsed.host.to_s.downcase)
      end

      def redirect_uri_allowlisted?(uri)
        patterns = config_value(:allowed_redirect_uri_patterns, nil)
        return true if patterns.nil?

        Array(patterns).any? { |pat| pat.is_a?(Regexp) ? full_match?(pat, uri.to_s) : pat.to_s == uri.to_s }
      end

      # A Regexp must match the WHOLE URI, even if the operator forgot \A/\z —
      # otherwise %r{https://claude\.ai/cb} would accept
      # https://evil.example/?x=https://claude.ai/cb.
      def full_match?(pattern, string)
        match = pattern.match(string)
        !match.nil? && match.begin(0).zero? && match.end(0) == string.length
      end

      # Reject (strict) or narrow (non-strict) scopes the server doesn't know, so
      # `*` / `admin` can't be registered and echoed back.
      def validate_scope_known
        return if scope.blank?

        unknown = Mcp::Auth::ScopeRegistry.unknown_scopes(scope)
        return if unknown.empty?

        if config_value(:strict_scope_validation, true) != false
          errors.add(:scope, "contains unsupported scope(s): #{unknown.join(' ')}")
        else
          self.scope = (scope.split - unknown).join(' ')
        end
      end

      def validate_client_uri
        return if client_uri.blank?

        parsed = URI.parse(client_uri.to_s)
        errors.add(:client_uri, 'must be an http(s) URL') unless parsed.is_a?(URI::HTTP) && parsed.host.present?
      rescue URI::InvalidURIError
        errors.add(:client_uri, 'must be an http(s) URL')
      end

      # Boolean settings are compared against an explicit `false` by the callers,
      # so nil (unset) means the documented default — matching the controller.
      def config_value(key, default)
        config = Mcp::Auth.configuration
        config.respond_to?(key) ? config.public_send(key) : default
      end

      def valid_redirect_uri_format?(uri)
        parsed = URI.parse(uri.to_s)
        return false if FORBIDDEN_REDIRECT_SCHEMES.include?(parsed.scheme.to_s.downcase)
        return true if parsed.is_a?(URI::HTTP) && parsed.host.present? # http(s) with host
        return true if parsed.scheme.present? && uri.to_s.include?('://') # native app scheme

        false
      rescue URI::InvalidURIError
        false
      end
    end
  end
end
