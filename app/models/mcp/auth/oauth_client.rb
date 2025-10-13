# frozen_string_literal: true

module Mcp
  module Auth
    class OauthClient < ApplicationRecord
      self.table_name = "mcp_auth_oauth_clients"
      self.primary_key = "client_id"

      # Set defaults BEFORE validation
      before_validation :set_defaults, on: :create

      validates :client_id, presence: true, uniqueness: true
      validates :client_secret, presence: true

      serialize :redirect_uris, coder: JSON
      serialize :grant_types, coder: JSON
      serialize :response_types, coder: JSON

      has_many :authorization_codes,
               class_name: "Mcp::Auth::AuthorizationCode",
               foreign_key: :client_id,
               primary_key: :client_id,
               dependent: :destroy

      has_many :access_tokens,
               class_name: "Mcp::Auth::AccessToken",
               foreign_key: :client_id,
               primary_key: :client_id,
               dependent: :destroy

      has_many :refresh_tokens,
               class_name: "Mcp::Auth::RefreshToken",
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
        self.scope ||= 'mcp:read mcp:write'
      end
    end
  end
end
