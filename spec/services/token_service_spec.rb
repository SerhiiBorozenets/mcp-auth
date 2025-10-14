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
      token_str = described_class.generate_access_token(access_token_params.merge(expires_at: 1.second.ago), base_url: base_url)
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
end
