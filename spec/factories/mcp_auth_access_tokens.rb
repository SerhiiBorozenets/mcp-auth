# frozen_string_literal: true

FactoryBot.define do
  factory :access_token, class: 'Mcp::Auth::AccessToken' do
    transient { raw_token { SecureRandom.hex(32) } }

    association :user, factory: :user
    association :org, factory: :org
    association :oauth_client, factory: :oauth_client

    # Stored hashed at rest; tests present `plaintext_token`.
    token { Mcp::Auth::SecretHashing.digest(raw_token) }
    client_id { oauth_client.client_id }
    scope { 'mcp:read mcp:write' }
    resource { 'http://localhost:3000/mcp' }
    expires_at { 1.hour.from_now }

    after(:build) { |record, evaluator| record.plaintext_token = evaluator.raw_token }
  end
end