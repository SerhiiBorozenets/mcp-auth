# frozen_string_literal: true

FactoryBot.define do
  factory :refresh_token, class: 'Mcp::Auth::RefreshToken' do
    association :user, factory: :user
    association :org, factory: :org
    association :oauth_client, factory: :oauth_client

    token { SecureRandom.hex(32) }
    client_id { oauth_client.client_id }
    scope { 'mcp:read mcp:write' }
    expires_at { 30.days.from_now }
  end
end
