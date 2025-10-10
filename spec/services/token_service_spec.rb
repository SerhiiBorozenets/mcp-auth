# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::Services::TokenService do
  let(:user) { create(:user) }
  let(:org) { create(:org) }
  let(:base_url) { 'https://example.com' }
  let(:token_data) do
    {
      client_id: 'test-client-id',
      scope: 'mcp:read mcp:write',
      user_id: user.id,
      org_id: org.id,
      resource: 'https://example.com/mcp/api'
    }
  end

  describe '.generate_access_token' do
    it 'generates a valid JWT token' do
      token = described_class.generate_access_token(token_data, base_url: base_url)

      expect(token).to be_present
      expect(token).to be_a(String)
    end

    it 'includes required claims in the token' do
      token = described_class.generate_access_token(token_data, base_url: base_url)
      payload = described_class.validate_access_token(token)

      expect(payload[:iss]).to eq(base_url)
      expect(payload[:aud]).to eq('https://example.com/mcp/api')
      expect(payload[:sub]).to eq(user.id.to_s)
      expect(payload[:org]).to eq(org.id.to_s)
      expect(payload[:scope]).to eq('mcp:read mcp:write')
      expect(payload[:iat]).to be_present
      expect(payload[:exp]).to be_present
    end

    it 'stores the token in the database' do
      expect {
        described_class.generate_access_token(token_data, base_url: base_url)
      }.to change(Mcp::Auth::AccessToken, :count).by(1)
    end

    it 'normalizes the resource URI' do
      token = described_class.generate_access_token(
        token_data.merge(resource: 'https://Example.com:443/mcp/api/'),
        base_url: base_url
      )
      payload = described_class.validate_access_token(token)

      expect(payload[:aud]).to eq('https://example.com/mcp/api')
    end
  end

  describe '.validate_access_token' do
    let(:token) { described_class.generate_access_token(token_data, base_url: base_url) }

    it 'validates a valid token' do
      payload = described_class.validate_access_token(token)

      expect(payload).to be_present
      expect(payload[:sub]).to eq(user.id.to_s)
    end

    it 'validates token with matching resource' do
      payload = described_class.validate_access_token(
        token,
        resource: 'https://example.com/mcp/api'
      )

      expect(payload).to be_present
    end

    it 'validates token when resource is a prefix' do
      payload = described_class.validate_access_token(
        token,
        resource: 'https://example.com/mcp/api/tools'
      )

      expect(payload).to be_present
    end

    it 'rejects token with mismatched resource' do
      payload = described_class.validate_access_token(
        token,
        resource: 'https://other.com/mcp/api'
      )

      expect(payload).to be_nil
    end

    it 'rejects expired token' do
      travel_to(2.hours.from_now) do
        payload = described_class.validate_access_token(token)
        expect(payload).to be_nil
      end
    end

    it 'rejects invalid token' do
      payload = described_class.validate_access_token('invalid.token.here')
      expect(payload).to be_nil
    end

    it 'rejects blank token' do
      payload = described_class.validate_access_token('')
      expect(payload).to be_nil
    end
  end

  describe '.generate_refresh_token' do
    it 'generates a refresh token' do
      refresh_token = described_class.generate_refresh_token(token_data)

      expect(refresh_token).to be_present
      expect(refresh_token).to be_a(String)
      expect(refresh_token.length).to eq(64) # hex(32) = 64 chars
    end

    it 'stores the refresh token in the database' do
      expect {
        described_class.generate_refresh_token(token_data)
      }.to change(Mcp::Auth::RefreshToken, :count).by(1)
    end

    it 'sets the correct expiration' do
      refresh_token = described_class.generate_refresh_token(token_data)
      record = Mcp::Auth::RefreshToken.find_by(token: refresh_token)

      expect(record.expires_at).to be_within(1.minute).of(30.days.from_now)
    end
  end

  describe '.validate_refresh_token' do
    let(:refresh_token) { described_class.generate_refresh_token(token_data) }

    it 'validates a valid refresh token' do
      data = described_class.validate_refresh_token(refresh_token)

      expect(data).to be_present
      expect(data[:client_id]).to eq('test-client-id')
      expect(data[:user_id]).to eq(user.id)
      expect(data[:org_id]).to eq(org.id)
    end

    it 'rejects expired refresh token' do
      travel_to(31.days.from_now) do
        data = described_class.validate_refresh_token(refresh_token)
        expect(data).to be_nil
      end
    end

    it 'rejects invalid refresh token' do
      data = described_class.validate_refresh_token('invalid-token')
      expect(data).to be_nil
    end
  end

  describe '.revoke_refresh_token' do
    let(:refresh_token) { described_class.generate_refresh_token(token_data) }

    it 'revokes a refresh token' do
      result = described_class.revoke_refresh_token(refresh_token)

      expect(result).to be true
      expect(Mcp::Auth::RefreshToken.find_by(token: refresh_token)).to be_nil
    end

    it 'returns false for non-existent token' do
      result = described_class.revoke_refresh_token('non-existent')
      expect(result).to be false
    end
  end

  describe '.generate_token_response' do
    it 'generates a complete token response' do
      response = described_class.generate_token_response(token_data, base_url: base_url)

      expect(response[:access_token]).to be_present
      expect(response[:token_type]).to eq('Bearer')
      expect(response[:expires_in]).to eq(3600)
      expect(response[:scope]).to eq('mcp:read mcp:write')
      expect(response[:refresh_token]).to be_present
    end
  end
end
