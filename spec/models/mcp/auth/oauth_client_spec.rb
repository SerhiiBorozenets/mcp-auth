# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::OauthClient, type: :model do
  subject { build(:oauth_client, client_id: 'test-client', client_secret: 'secret') }

  describe 'validations' do
    it { should validate_uniqueness_of(:client_id) }
  end

  describe 'associations' do
    it { should have_many(:authorization_codes).dependent(:destroy) }
    it { should have_many(:access_tokens).dependent(:destroy) }
    it { should have_many(:refresh_tokens).dependent(:destroy) }
  end

  describe 'callbacks' do
    context 'on create' do
      it 'sets default values' do
        client = described_class.create!(client_name: 'Test Client')

        expect(client.client_id).to be_present
        expect(client.client_secret).to be_present
        expect(client.grant_types).to eq(%w[authorization_code refresh_token])
        expect(client.response_types).to eq(['code'])
        expect(client.scope).to eq('mcp:read mcp:write')
      end
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
