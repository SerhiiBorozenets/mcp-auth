# frozen_string_literal: true

module Mcp
  module Auth
    class OauthClient < ActiveRecord::Base
      self.table_name = 'mcp_auth_oauth_clients'
      self.primary_key = 'client_id'

      # Set defaults BEFORE validation
      before_validation :set_defaults, on: :create

      validates :client_id, presence: true, uniqueness: true
      validates :client_secret, presence: true
      validate :validate_redirect_uris

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

      def self.find_by_client_id(client_id)
        find_by(client_id: client_id)
      end

      def valid_redirect_uri?(uri)
        redirect_uris&.include?(uri)
      end

      def supports_grant_type?(grant_type)
        grant_types&.include?(grant_type)
      end

      private

      def set_defaults
        self.client_id ||= SecureRandom.uuid
        self.client_secret ||= SecureRandom.hex(32)
        self.grant_types ||= %w[authorization_code refresh_token]
        self.response_types ||= %w[code]
        self.scope ||= Mcp::Auth::ScopeRegistry.default_scope_string
      end

      # RFC 7591 / RFC 8252: a client using the authorization_code grant must
      # register at least one redirect URI, and each must be an absolute URI.
      # We reject scheme-only values (e.g. `javascript:`/`data:`) that would be
      # XSS-redirect vectors, while still allowing http(s) and native app schemes.
      def validate_redirect_uris
        return unless Array(grant_types).include?('authorization_code')

        uris = Array(redirect_uris)
        if uris.empty?
          errors.add(:redirect_uris, 'must include at least one redirect URI')
          return
        end

        uris.each do |uri|
          errors.add(:redirect_uris, "contains an invalid redirect URI: #{uri}") unless valid_redirect_uri_format?(uri)
        end
      end

      def valid_redirect_uri_format?(uri)
        parsed = URI.parse(uri.to_s)
        return true if parsed.is_a?(URI::HTTP) && parsed.host.present? # http(s) with host
        return true if parsed.scheme.present? && uri.to_s.include?('://') # native app scheme

        false
      rescue URI::InvalidURIError
        false
      end
    end
  end
end
