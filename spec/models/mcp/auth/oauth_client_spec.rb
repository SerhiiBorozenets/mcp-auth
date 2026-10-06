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

    it 'rejects script/local schemes even when written with ://' do
      %w[javascript://%0aalert(1) JavaScript://x data://text/html,x file:///etc/passwd vbscript://x].each do |uri|
        expect(build(:oauth_client, redirect_uris: [uri])).not_to be_valid, "expected #{uri} to be rejected"
      end
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
  describe 'DCR redirect/scope policy' do
    let(:attrs) { { client_name: 'X', redirect_uris: ['https://c.example.com/cb'] } }

    it 'allows https, loopback http on any port, and native schemes' do
      %w[https://c.example.com/cb http://localhost:8123/cb http://127.0.0.1/cb http://[::1]:9/cb cursor://auth/cb].each do |uri|
        expect(described_class.new(attrs.merge(redirect_uris: [uri]))).to be_valid, uri
      end
    end

    it 'rejects http on a non-loopback host' do
      expect(described_class.new(attrs.merge(redirect_uris: ['http://evil.example.com/cb']))).not_to be_valid
    end

    it 'can disable loopback redirects' do
      allow(Mcp::Auth.configuration).to receive(:allow_loopback_redirects).and_return(false)
      expect(described_class.new(attrs.merge(redirect_uris: ['http://localhost:1/cb']))).not_to be_valid
    end

    it 'enforces the allowlist for non-loopback URIs when configured' do
      allow(Mcp::Auth.configuration).to receive(:allowed_redirect_uri_patterns)
        .and_return(['https://claude.ai/api/mcp/auth_callback'])

      expect(described_class.new(attrs.merge(redirect_uris: ['https://claude.ai/api/mcp/auth_callback']))).to be_valid
      expect(described_class.new(attrs)).not_to be_valid
    end

    it 'applies the redirect policy even when the client did not register authorization_code' do
      refresh_only = attrs.merge(grant_types: %w[refresh_token])

      expect(described_class.new(refresh_only.merge(redirect_uris: ['http://evil.example/cb']))).not_to be_valid

      allow(Mcp::Auth.configuration).to receive(:allowed_redirect_uri_patterns)
        .and_return(['https://claude.ai/api/mcp/auth_callback'])
      expect(described_class.new(refresh_only.merge(redirect_uris: ['https://evil.example/cb']))).not_to be_valid
    end

    it 'requires an allowlist Regexp to match the WHOLE URI, even when not anchored' do
      allow(Mcp::Auth.configuration).to receive(:allowed_redirect_uri_patterns)
        .and_return([%r{https://claude\.ai/api/mcp/auth_callback}])

      expect(described_class.new(attrs.merge(redirect_uris: ['https://claude.ai/api/mcp/auth_callback']))).to be_valid
      %w[https://evil.example/?x=https://claude.ai/api/mcp/auth_callback
         https://claude.ai/api/mcp/auth_callback.evil.example].each do |uri|
        expect(described_class.new(attrs.merge(redirect_uris: [uri]))).not_to be_valid, uri
      end
    end

    it 'treats unset (nil) policy settings as their documented defaults' do
      allow(Mcp::Auth.configuration).to receive(:allow_loopback_redirects).and_return(nil)
      allow(Mcp::Auth.configuration).to receive(:strict_scope_validation).and_return(nil)

      expect(described_class.new(attrs.merge(redirect_uris: ['http://localhost:1/cb']))).to be_valid
      expect(described_class.new(attrs.merge(scope: 'mcp:read admin'))).not_to be_valid
    end

    it 'rejects unknown scopes when strict, and narrows them when not' do
      expect(described_class.new(attrs.merge(scope: 'mcp:read admin *'))).not_to be_valid

      allow(Mcp::Auth.configuration).to receive(:strict_scope_validation).and_return(false)
      client = described_class.new(attrs.merge(scope: 'mcp:read admin *'))
      expect(client).to be_valid
      expect(client.scope).to eq('mcp:read')
    end

    it 'accepts OIDC scopes' do
      expect(described_class.new(attrs.merge(scope: 'openid profile email mcp:read'))).to be_valid
    end

    it 'requires client_uri to be an http(s) URL' do
      expect(described_class.new(attrs.merge(client_uri: 'javascript:alert(1)'))).not_to be_valid
      expect(described_class.new(attrs.merge(client_uri: 'https://c.example.com'))).to be_valid
    end
  end
end
