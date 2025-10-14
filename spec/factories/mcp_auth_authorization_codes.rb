# frozen_string_literal: true

FactoryBot.define do
  factory :authorization_code, class: 'Mcp::Auth::AuthorizationCode' do
    association :user, factory: :user
    association :org, factory: :org
    association :oauth_client, factory: :oauth_client

    code { SecureRandom.hex(32) }
    client_id { oauth_client.client_id }
    redirect_uri { 'http://localhost:3000/callback' }
    code_challenge { Base64.urlsafe_encode64(Digest::SHA256.digest('test_verifier'), padding: false) }
    code_challenge_method { 'S256' }
    scope { 'mcp:read mcp:write' }
    resource { 'http://localhost:3000/mcp/api' }
    expires_at { 30.minutes.from_now }
  end
end
