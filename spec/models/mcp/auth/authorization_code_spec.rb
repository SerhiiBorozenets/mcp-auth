# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::AuthorizationCode, type: :model do
  describe 'validations' do
    it { should validate_presence_of(:code) }
    it { should validate_presence_of(:client_id) }
    it { should validate_presence_of(:redirect_uri) }
    it { should validate_presence_of(:expires_at) }
  end

  describe 'associations' do
    it { should belong_to(:user) }
    it { should belong_to(:org).optional }
    it { should belong_to(:oauth_client).optional }
  end

  describe 'scopes' do
    let!(:active_code) { create(:authorization_code, expires_at: 1.hour.from_now) }
    let!(:expired_code) { create(:authorization_code, expires_at: 1.hour.ago) }

    describe '.active' do
      it 'returns only active codes' do
        expect(described_class.active).to include(active_code)
        expect(described_class.active).not_to include(expired_code)
      end
    end

    describe '.expired' do
      it 'returns only expired codes' do
        expect(described_class.expired).to include(expired_code)
        expect(described_class.expired).not_to include(active_code)
      end
    end
  end

  describe '#expired?' do
    it 'returns false for non-expired code' do
      code = create(:authorization_code, expires_at: 1.hour.from_now)
      expect(code.expired?).to be false
    end

    it 'returns true for expired code' do
      code = create(:authorization_code, expires_at: 1.hour.ago)
      expect(code.expired?).to be true
    end
  end

  describe '.cleanup_expired' do
    let!(:active_code) { create(:authorization_code, expires_at: 1.hour.from_now) }
    let!(:expired_code) { create(:authorization_code, expires_at: 1.hour.ago) }

    it 'deletes expired codes' do
      expect {
        described_class.cleanup_expired
      }.to change(described_class, :count).by(-1)

      expect(described_class.exists?(expired_code.id)).to be false
      expect(described_class.exists?(active_code.id)).to be true
    end
  end
end
