# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::Services::TokenService, 'asymmetric signing (CP-9255 batch 2)' do
  let(:user) { create(:user) }
  let(:org) { create(:org) }
  let(:oauth_client) { create(:oauth_client) }
  let(:base_url) { 'http://localhost:3000' }
  let(:token_params) do
    {
      client_id: oauth_client.client_id,
      user_id: user.id,
      org_id: org.id,
      scope: 'mcp:read mcp:write',
      expires_at: 1.hour.from_now
    }
  end

  # The TokenService caches keys at module level; reset between examples
  # so each context's config takes effect.
  before do
    Mcp::Auth::Services::TokenService.instance_variable_set(:@cached_private_key, nil)
    Mcp::Auth::Services::TokenService.instance_variable_set(:@cached_public_key, nil)
    Mcp::Auth::Services::TokenService.instance_variable_set(:@jwk, nil)
  end

  describe 'default (HS256) behaviour' do
    it 'signs and validates tokens with HS256 when no asymmetric keys are configured' do
      token = described_class.generate_access_token(token_params, base_url: base_url)

      header = JSON.parse(Base64.urlsafe_decode64(token.split('.').first))
      expect(header['alg']).to eq('HS256')
      expect(header['kid']).to be_nil

      payload = described_class.validate_access_token(token)
      expect(payload[:sub]).to eq(user.id.to_s)
    end

    it 'returns nil for signing_jwk_export when HS256 is in use' do
      expect(described_class.signing_jwk_export).to be_nil
    end
  end

  describe 'RS256' do
    let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }

    before do
      Mcp::Auth.configure do |c|
        c.token_signing_algorithm = 'RS256'
        c.token_signing_private_key = rsa_key.to_pem
      end
    end

    after do
      Mcp::Auth.configure do |c|
        c.token_signing_algorithm = 'HS256'
        c.token_signing_private_key = nil
        c.token_signing_public_key = nil
        c.token_signing_kid = nil
      end
    end

    it 'signs JWTs with RS256 and includes kid in the header' do
      token = described_class.generate_access_token(token_params, base_url: base_url)

      header = JSON.parse(Base64.urlsafe_decode64(token.split('.').first))
      expect(header['alg']).to eq('RS256')
      expect(header['kid']).to be_present
    end

    it 'validates RS256-signed tokens with the configured public key' do
      token = described_class.generate_access_token(token_params, base_url: base_url)
      payload = described_class.validate_access_token(token)

      expect(payload[:sub]).to eq(user.id.to_s)
      expect(payload[:scope]).to eq('mcp:read mcp:write')
    end

    it 'returns a JWKS-shaped hash from signing_jwk_export' do
      jwk = described_class.signing_jwk_export

      expect(jwk[:kty]).to eq('RSA')
      expect(jwk[:use]).to eq('sig')
      expect(jwk[:alg]).to eq('RS256')
      expect(jwk[:kid]).to be_present
      expect(jwk[:n]).to be_present
      expect(jwk[:e]).to be_present
      expect(jwk).not_to have_key(:d) # never expose private exponent
    end

    it 'honours an explicit token_signing_kid override' do
      Mcp::Auth.configure { |c| c.token_signing_kid = 'main-2026-05' }

      token = described_class.generate_access_token(token_params, base_url: base_url)
      header = JSON.parse(Base64.urlsafe_decode64(token.split('.').first))

      expect(header['kid']).to eq('main-2026-05')
      expect(described_class.signing_jwk_export[:kid]).to eq('main-2026-05')
    end
  end

  describe 'ES256' do
    let(:ec_key) do
      key = OpenSSL::PKey::EC.new('prime256v1')
      key.generate_key
      key
    end

    before do
      Mcp::Auth.configure do |c|
        c.token_signing_algorithm = 'ES256'
        c.token_signing_private_key = ec_key.to_pem
      end
    end

    after do
      Mcp::Auth.configure do |c|
        c.token_signing_algorithm = 'HS256'
        c.token_signing_private_key = nil
        c.token_signing_public_key = nil
        c.token_signing_kid = nil
      end
    end

    it 'signs and validates with ES256' do
      token = described_class.generate_access_token(token_params, base_url: base_url)

      header = JSON.parse(Base64.urlsafe_decode64(token.split('.').first))
      expect(header['alg']).to eq('ES256')

      payload = described_class.validate_access_token(token)
      expect(payload[:sub]).to eq(user.id.to_s)
    end

    it 'exports an EC JWK without private fields' do
      jwk = described_class.signing_jwk_export

      expect(jwk[:kty]).to eq('EC')
      expect(jwk[:crv]).to eq('P-256')
      expect(jwk[:alg]).to eq('ES256')
      expect(jwk[:x]).to be_present
      expect(jwk[:y]).to be_present
      expect(jwk).not_to have_key(:d) # never expose private scalar
    end
  end

  describe 'configuration validation' do
    after do
      Mcp::Auth.configure { |c| c.token_signing_algorithm = 'HS256' }
    end

    it 'rejects unknown algorithms' do
      expect {
        Mcp::Auth.configure { |c| c.token_signing_algorithm = 'XYZ999' }
      }.to raise_error(ArgumentError, /Unsupported token_signing_algorithm/)
    end

    it 'accepts the supported algorithms (case-insensitive)' do
      expect {
        Mcp::Auth.configure { |c| c.token_signing_algorithm = 'rs256' }
      }.not_to raise_error
      expect(Mcp::Auth.configuration.token_signing_algorithm).to eq('RS256')
    end
  end
end
