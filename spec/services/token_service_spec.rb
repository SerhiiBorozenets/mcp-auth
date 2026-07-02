# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::Services::TokenService do
  let(:user) { create(:user) }
  let(:org) { create(:org) }
  let(:oauth_client) { create(:oauth_client) }
  let(:base_url) { 'http://localhost:3000' }
  let(:access_token_params) do
    {
      client_id: oauth_client.client_id,
      user_id: user.id,
      org_id: org.id,
      scope: 'mcp:read mcp:write',
      expires_at: 1.hour.from_now
    }
  end

  let(:refresh_token_params) do
    {
      client_id: oauth_client.client_id,
      user_id: user.id,
      org_id: org.id,
      scope: 'mcp:read mcp:write',
      expires_at: 1.day.from_now
    }
  end

  describe '.generate_access_token' do
    it 'creates a new access token' do
      token_str = described_class.generate_access_token(access_token_params, base_url: base_url)
      expect(token_str).to be_present
      expect(token_str).to be_a(String)
      # Optionally decode and check payload if needed
    end
  end

  describe '.generate_access_token sensitive-claim hygiene' do
    it 'embeds the api_key_id but never the api_key_secret' do
      allow(Mcp::Auth.configuration).to receive(:fetch_user_data).and_return(
        proc { |_data| { email: 't@example.com', api_key_id: 'key-123', api_key_secret: 'SUPER-SECRET' } }
      )

      token = described_class.generate_access_token(access_token_params, base_url: base_url)
      payload = JWT.decode(token, nil, false).first

      expect(payload['api_key_id']).to eq('key-123')
      expect(payload).not_to have_key('api_key_secret')
    end
  end

  describe '.validate_access_token' do
    it 'returns token data for valid token' do
      token_str = described_class.generate_access_token(access_token_params, base_url: base_url)
      data = described_class.validate_access_token(token_str)
      expect(data).to be_present
      expect(data[:sub]).to eq(user.id.to_s)
      expect(data[:org]).to eq(org.id.to_s)
      expect(data[:client_id]).to eq(oauth_client.client_id)
    end

    it 'returns nil for expired token' do
      token_str = described_class.generate_access_token(access_token_params.merge(expires_at: 1.second.ago),
                                                        base_url: base_url)
      data = described_class.validate_access_token(token_str)
      expect(data).to be_nil
    end

    it 'returns nil for invalid token' do
      data = described_class.validate_access_token('invalid-token')
      expect(data).to be_nil
    end
  end

  describe '.generate_refresh_token' do
    it 'creates a new refresh token' do
      refresh_token_str = described_class.generate_refresh_token(refresh_token_params)
      expect(refresh_token_str).to be_present
      expect(refresh_token_str).to be_a(String)
      # Optionally decode and check payload if needed
    end
  end

  describe '.validate_refresh_token' do
    it 'returns token data for valid refresh token' do
      refresh_token_str = described_class.generate_refresh_token(refresh_token_params)
      data = described_class.validate_refresh_token(refresh_token_str)
      expect(data).to be_present
      expect(data[:user_id]).to eq(user.id)
      expect(data[:org_id]).to eq(org.id)
      expect(data[:client_id]).to eq(oauth_client.client_id)
    end

    it 'returns nil for expired refresh token' do
      refresh_token_str = described_class.generate_refresh_token(refresh_token_params.merge(expires_at: 1.second.ago))
      data = described_class.validate_refresh_token(refresh_token_str)
      expect(data).to be_nil
    end

    it 'returns nil for invalid refresh token' do
      data = described_class.validate_refresh_token('invalid-token')
      expect(data).to be_nil
    end
  end

  describe 'access-token revocation takes effect (RFC 7009)' do
    it 'rejects a token once its stored row is destroyed' do
      token = described_class.generate_access_token(access_token_params, base_url: base_url)
      expect(described_class.validate_access_token(token)).to be_present

      Mcp::Auth::AccessToken.find_by(token: token).destroy
      expect(described_class.validate_access_token(token)).to be_nil
    end
  end

  describe 'RFC 8707 audience binding' do
    it 'defaults the audience to base_url + configured mcp_server_path' do
      allow(Mcp::Auth.configuration).to receive(:mcp_server_path).and_return('/api/mcp')

      token = described_class.generate_access_token(access_token_params, base_url: base_url)
      payload = JWT.decode(token, nil, false).first

      expect(payload['aud']).to eq('http://localhost:3000/api/mcp')
    end

    it 'matches the audience exactly and is not fooled by a string prefix' do
      params = access_token_params.merge(resource: 'https://api.example.com')
      token = described_class.generate_access_token(params, base_url: base_url)

      expect(described_class.validate_access_token(token, resource: 'https://api.example.com')).to be_present
      expect(described_class.validate_access_token(token, resource: 'https://api.example.com.evil.com')).to be_nil
    end

    it 'does not crash on a malformed resource indicator' do
      params = access_token_params.merge(resource: 'not a uri')
      expect { described_class.generate_access_token(params, base_url: base_url) }.not_to raise_error
    end
  end

  describe 'oauth_secret key separation (M7)' do
    it 'refuses to fall back to secret_key_base in production when unset' do
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new('production'))
      allow(Mcp::Auth.configuration).to receive(:oauth_secret).and_return(nil)

      expect { described_class.send(:oauth_secret) }
        .to raise_error(Mcp::Auth::Error, /oauth_secret/)
    end

    it 'uses the configured secret when present (no error)' do
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new('production'))
      allow(Mcp::Auth.configuration).to receive(:oauth_secret).and_return('dedicated-secret')

      expect(described_class.send(:oauth_secret)).to eq('dedicated-secret')
    end
  end

  describe 'JWT validation hardening (H3)' do
    def sign(payload)
      JWT.encode(payload, 'test_secret', 'HS256')
    end

    def store_row(token)
      Mcp::Auth::AccessToken.create!(
        token: token, client_id: oauth_client.client_id, resource: "#{base_url}/mcp",
        scope: 'mcp:read', user_id: user.id, expires_at: 1.hour.from_now
      )
    end

    let(:now) { Time.current.to_i }

    it 'rejects an id_token presented as an access token, even when a stored row exists' do
      forged = sign(iss: base_url, aud: oauth_client.client_id, sub: user.id.to_s,
                    token_use: 'id', iat: now, exp: now + 3600)
      store_row(forged) # bypass the revocation/DB gate to isolate the token_use check

      expect(described_class.validate_access_token(forged)).to be_nil
    end

    it 'rejects a token missing the required aud claim' do
      forged = sign(iss: base_url, sub: user.id.to_s, token_use: 'access', iat: now, exp: now + 3600)
      store_row(forged)

      expect(described_class.validate_access_token(forged)).to be_nil
    end

    it 'still accepts a well-formed access token carrying token_use=access' do
      token = described_class.generate_access_token(access_token_params, base_url: base_url)
      payload = JWT.decode(token, nil, false).first

      expect(payload['token_use']).to eq('access')
      expect(described_class.validate_access_token(token)).to be_present
    end
  end

  describe 'OpenID Connect id_token' do
    it 'is issued when the openid scope is granted' do
      response = described_class.generate_token_response(
        access_token_params.merge(scope: 'openid email mcp:read'),
        base_url: base_url
      )

      expect(response[:id_token]).to be_present
      id_payload = JWT.decode(response[:id_token], nil, false).first
      expect(id_payload['aud']).to eq(oauth_client.client_id)
      expect(id_payload['email']).to eq('test@example.com')
    end

    it 'is omitted when the openid scope is absent' do
      response = described_class.generate_token_response(access_token_params, base_url: base_url)
      expect(response).not_to have_key(:id_token)
    end
  end
end
