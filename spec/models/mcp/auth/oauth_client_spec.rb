# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::OauthClient, type: :model do
  subject { build(:oauth_client, client_id: 'test-client', client_secret: 'secret') }

  describe 'validations' do
    it { is_expected.to validate_uniqueness_of(:client_id) }
  end

  describe 'associations' do
    it { is_expected.to have_many(:authorization_codes).dependent(:destroy) }
    it { is_expected.to have_many(:access_tokens).dependent(:destroy) }
    it { is_expected.to have_many(:refresh_tokens).dependent(:destroy) }
  end

  describe 'callbacks' do
    context 'on create' do
      it 'sets default values' do
        client = described_class.create!(
          client_name: 'Test Client',
          redirect_uris: ['https://example.com/callback']
        )

        expect(client.client_id).to be_present
        expect(client.client_secret).to be_present
        expect(client.grant_types).to eq(%w[authorization_code refresh_token])
        expect(client.response_types).to eq(['code'])
        expect(client.scope).to eq('mcp:read mcp:write')
      end
    end
  end

  describe 'client_secret hashing at rest (H5)' do
    let(:client) { described_class.create!(client_name: 'X', redirect_uris: ['https://e.com/cb']) }

    it 'stores a digest, not the plaintext, and exposes the plaintext once' do
      expect(client.plaintext_secret).to be_present
      expect(client.client_secret).to start_with('sha256$')
      expect(client.client_secret).not_to eq(client.plaintext_secret)
    end

    it 'verifies a correct secret and rejects a wrong one' do
      expect(client.authenticate_secret(client.plaintext_secret)).to be true
      expect(client.authenticate_secret('wrong')).to be false
    end

    it 'authenticates a legacy plaintext secret under dual-read, and rejects it once disabled' do
      legacy = create(:oauth_client)
      legacy.update_column(:client_secret, 'legacy-plaintext') # pre-migration row

      expect(legacy.authenticate_secret('legacy-plaintext')).to be true

      allow(Mcp::Auth.configuration).to receive(:secret_dual_read).and_return(false)
      expect(legacy.authenticate_secret('legacy-plaintext')).to be false
    end
  end

  describe 'token_endpoint_auth_method (confidential vs public, H1)' do
    it 'defaults to none (public / PKCE client)' do
      client = described_class.create!(client_name: 'X', redirect_uris: ['https://e.com/cb'])
      expect(client.token_endpoint_auth_method).to eq('none')
      expect(client).not_to be_confidential
    end

    it 'is confidential when registered with client_secret_basic' do
      client = described_class.create!(
        client_name: 'X', redirect_uris: ['https://e.com/cb'], token_endpoint_auth_method: 'client_secret_basic'
      )
      expect(client).to be_confidential
    end

    it 'rejects an unsupported auth method' do
      expect(build(:oauth_client, token_endpoint_auth_method: 'private_key_jwt')).not_to be_valid
    end
  end

  describe 'redirect_uri validation (RFC 7591/8252)' do
    it 'rejects an authorization_code client with no redirect URIs' do
      client = build(:oauth_client, redirect_uris: [])
      expect(client).not_to be_valid
      expect(client.errors[:redirect_uris]).to be_present
    end

    it 'rejects a javascript: redirect URI' do
      client = build(:oauth_client, redirect_uris: ['javascript:alert(1)'])
      expect(client).not_to be_valid
    end

    it 'accepts an https redirect URI' do
      client = build(:oauth_client, redirect_uris: ['https://app.example.com/cb'])
      expect(client).to be_valid
    end

    it 'accepts a native app-scheme redirect URI' do
      client = build(:oauth_client, redirect_uris: ['com.example.app://oauth/cb'])
      expect(client).to be_valid
    end
  end

  describe '#valid_redirect_uri?' do
    let(:client) { create(:oauth_client, redirect_uris: ['http://localhost:3000/callback']) }

    it 'returns true for valid URI' do
      expect(client.valid_redirect_uri?('http://localhost:3000/callback')).to be true
    end

    it 'returns false for invalid URI' do
      expect(client.valid_redirect_uri?('http://evil.com/callback')).to be false
    end
  end

  describe '#supports_grant_type?' do
    let(:client) { create(:oauth_client) }

    it 'returns true for supported grant type' do
      expect(client.supports_grant_type?('authorization_code')).to be true
    end

    it 'returns false for unsupported grant type' do
      expect(client.supports_grant_type?('password')).to be false
    end
  end
end
