# frozen_string_literal: true

require 'rails_helper'
require_relative '../../../dummy/config/environment'

RSpec.describe Mcp::Auth::AccessToken, type: :model do
  let!(:user) { create(:user) }
  let!(:org) { create(:org) }
  let!(:oauth_client) { create(:oauth_client) }

  describe 'validations' do
    subject { build(:access_token, user: user, org: org, oauth_client: oauth_client) }

    it { should validate_presence_of(:token) }
    it { should validate_presence_of(:client_id) }
    it { should validate_presence_of(:expires_at) }
    it { should validate_uniqueness_of(:token) }
  end

  describe 'associations' do
    it { should belong_to(:user) }
    it { should belong_to(:org).optional }
    it { should belong_to(:oauth_client).optional }
  end

  describe 'scopes' do
    let!(:active_token) { create(:access_token, user: user, org: org, oauth_client: oauth_client, expires_at: 1.hour.from_now) }
    let!(:expired_token) { create(:access_token, user: user, org: org, oauth_client: oauth_client, expires_at: 1.hour.ago) }

    describe '.active' do
      it 'returns only active tokens' do
        expect(described_class.active).to include(active_token)
        expect(described_class.active).not_to include(expired_token)
      end
    end

    describe '.expired' do
      it 'returns only expired tokens' do
        expect(described_class.expired).to include(expired_token)
        expect(described_class.expired).not_to include(active_token)
      end
    end
  end

  describe '#expired?' do
    it 'returns false for non-expired token' do
      token = create(:access_token, user: user, org: org, oauth_client: oauth_client, expires_at: 1.hour.from_now)
      expect(token.expired?).to be false
    end

    it 'returns true for expired token' do
      token = create(:access_token, user: user, org: org, oauth_client: oauth_client, expires_at: 1.hour.ago)
      expect(token.expired?).to be true
    end
  end

  describe '.cleanup_expired' do
    let!(:active_token) { create(:access_token, user: user, org: org, oauth_client: oauth_client, expires_at: 1.hour.from_now) }
    let!(:expired_token) { create(:access_token, user: user, org: org, oauth_client: oauth_client, expires_at: 1.hour.ago) }

    it 'deletes expired tokens' do
      expect {
        described_class.cleanup_expired
      }.to change(described_class, :count).by(-1)

      expect(described_class.exists?(expired_token.id)).to be false
      expect(described_class.exists?(active_token.id)).to be true
    end
  end
end
