# frozen_string_literal: true

FactoryBot.define do
  factory :access_token, class: 'Mcp::Auth::AccessToken' do
    association :user, factory: :user
    association :org, factory: :org
    association :oauth_client, factory: :oauth_client

    token { SecureRandom.hex(32) }
    client_id { oauth_client.client_id }
    scope { 'mcp:read mcp:write' }
    resource { 'http://localhost:3000/mcp/api' }
    expires_at { 1.hour.from_now }
  end
end