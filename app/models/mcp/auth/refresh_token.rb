# frozen_string_literal: true

module Mcp
  module Auth
    class RefreshToken < ActiveRecord::Base
      self.table_name = "mcp_auth_refresh_tokens"

      belongs_to :user
      belongs_to :org, optional: true
      belongs_to :oauth_client,
                 class_name: "Mcp::Auth::OauthClient",
                 foreign_key: :client_id,
                 primary_key: :client_id,
                 optional: true

      # Plaintext token, available only in memory (never persisted); the `token`
      # column stores the digest.
      attr_accessor :plaintext_token

      validates :token, presence: true, uniqueness: true
      validates :client_id, presence: true
      validates :expires_at, presence: true

      # A token is "live" only if it is neither expired nor revoked. Rotation
      # marks the presented token revoked (rather than deleting it) so that a
      # later replay of the same token can be DETECTED as reuse.
      scope :active, -> { where(revoked_at: nil).where('expires_at > ?', Time.current) }
      scope :expired, -> { where('expires_at <= ?', Time.current) }

      def expired?
        expires_at <= Time.current
      end

      def revoked?
        revoked_at.present?
      end

      def self.cleanup_expired
        expired.delete_all
      end
    end
  end
end
