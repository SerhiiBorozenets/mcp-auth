# frozen_string_literal: true

FactoryBot.define do
  factory :oauth_client, class: 'Mcp::Auth::OauthClient' do
    client_name { Faker::App.name }
    redirect_uris { ['http://localhost:3000/callback'] }
    grant_types { %w[authorization_code refresh_token] }
    response_types { ['code'] }
    scope { 'mcp:read mcp:write' }
  end
end