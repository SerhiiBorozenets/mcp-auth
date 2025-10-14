# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::RefreshToken, type: :model do
  subject { build(:refresh_token, token: 'unique-token', client_id: 'client', expires_at: 1.day.from_now) }

  describe 'validations' do
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
    let!(:active_token) { create(:refresh_token, expires_at: 30.days.from_now) }
    let!(:expired_token) { create(:refresh_token, expires_at: 1.day.ago) }

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
      token = create(:refresh_token, expires_at: 30.days.from_now)
      expect(token.expired?).to be false
    end

    it 'returns true for expired token' do
      token = create(:refresh_token, expires_at: 1.day.ago)
      expect(token.expired?).to be true
    end
  end

  describe '.cleanup_expired' do
    let!(:active_token) { create(:refresh_token, expires_at: 30.days.from_now) }
    let!(:expired_token) { create(:refresh_token, expires_at: 1.day.ago) }

    it 'deletes expired tokens' do
      expect {
        described_class.cleanup_expired
      }.to change(described_class, :count).by(-1)

      expect(described_class.exists?(expired_token.id)).to be false
      expect(described_class.exists?(active_token.id)).to be true
    end
  end
end
