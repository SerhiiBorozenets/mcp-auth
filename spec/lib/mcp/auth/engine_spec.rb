# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::Engine do
  it 'filters OAuth credentials, including the code and PKCE verifier, from logs' do
    filter = ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters)
    filtered = filter.filter('code' => 'c', 'code_verifier' => 'v', 'refresh_token' => 'r', 'client_secret' => 's')

    expect(filtered.values).to all(eq('[FILTERED]'))
  end

  it 'matches OAuth names exactly, not as substrings of unrelated host-app params' do
    filter = ActiveSupport::ParameterFilter.new(Mcp::Auth::Engine::OAUTH_FILTER_PARAMETERS)

    expect(filter.filter('postal_code' => '12345', 'promo_code' => 'X', 'tokenizer' => 't'))
      .to eq('postal_code' => '12345', 'promo_code' => 'X', 'tokenizer' => 't')
  end

  it 'filters redirects that carry an authorization code' do
    expect(Rails.application.config.filter_redirect.grep(Regexp).any? { |re| re.match?('https://c.example/cb?code=abc') })
      .to be true
  end
end
