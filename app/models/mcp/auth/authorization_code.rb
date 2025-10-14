# frozen_string_literal: true

module Mcp
  module Auth
    class AuthorizationCode < ActiveRecord::Base
      self.table_name = "mcp_auth_authorization_codes"

      belongs_to :user
      belongs_to :org, optional: true
      belongs_to :oauth_client,
                 class_name: "Mcp::Auth::OauthClient",
                 foreign_key: :client_id,
                 primary_key: :client_id,
                 optional: true

      validates :code, presence: true, uniqueness: true
      validates :client_id, presence: true
      validates :redirect_uri, presence: true
      validates :expires_at, presence: true

      scope :active, -> { where('expires_at > ?', Time.current) }
      scope :expired, -> { where('expires_at <= ?', Time.current) }

      def expired?
        expires_at <= Time.current
      end

      def self.cleanup_expired
        expired.delete_all
      end
    end
  end
end
