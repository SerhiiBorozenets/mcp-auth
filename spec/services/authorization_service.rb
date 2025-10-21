# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::Services::AuthorizationService do
  let(:user) { create(:user) }
  let(:org) { create(:org) }
  let(:oauth_client) { create(:oauth_client) }
  let(:params) do
    {
      client_id: oauth_client.client_id,
      redirect_uri: 'http://localhost:3000/callback',
      code_challenge: Base64.urlsafe_encode64(Digest::SHA256.digest('test_verifier'), padding: false),
      code_challenge_method: 'S256',
      resource: 'http://localhost:3000/mcp',
      scope: 'mcp:read mcp:write'
    }
  end

  describe '.generate_authorization_code' do
    it 'generates an authorization code' do
      code = described_class.generate_authorization_code(params, user: user, org: org)

      expect(code).to be_present
      expect(code).to be_a(String)
      expect(code.length).to eq(64) # hex(32) = 64 chars
    end

    it 'stores the code in the database' do
      expect {
        described_class.generate_authorization_code(params, user: user, org: org)
      }.to change(Mcp::Auth::AuthorizationCode, :count).by(1)
    end

    it 'sets correct attributes' do
      code = described_class.generate_authorization_code(params, user: user, org: org)
      record = Mcp::Auth::AuthorizationCode.find_by(code: code)

      expect(record.user).to eq(user)
      expect(record.org).to eq(org)
      expect(record.client_id).to eq(oauth_client.client_id)
      expect(record.redirect_uri).to eq(params[:redirect_uri])
      expect(record.code_challenge).to eq(params[:code_challenge])
      expect(record.resource).to eq(params[:resource])
      expect(record.scope).to eq(params[:scope])
    end

    it 'sets expiration to 30 minutes' do
      code = described_class.generate_authorization_code(params, user: user, org: org)
      record = Mcp::Auth::AuthorizationCode.find_by(code: code)

      expect(record.expires_at).to be_within(1.minute).of(30.minutes.from_now)
    end
  end

  describe '.validate_authorization_code' do
    let(:code) { described_class.generate_authorization_code(params, user: user, org: org) }

    it 'validates a valid code' do
      data = described_class.validate_authorization_code(code)

      expect(data).to be_present
      expect(data[:client_id]).to eq(oauth_client.client_id)
      expect(data[:user_id]).to eq(user.id)
      expect(data[:org_id]).to eq(org.id)
      expect(data[:code_challenge]).to eq(params[:code_challenge])
    end

    it 'returns nil for expired code' do
      travel_to(31.minutes.from_now) do
        data = described_class.validate_authorization_code(code)
        expect(data).to be_nil
      end
    end

    it 'returns nil for invalid code' do
      data = described_class.validate_authorization_code('invalid-code')
      expect(data).to be_nil
    end
  end

  describe '.consume_authorization_code' do
    let(:code) { described_class.generate_authorization_code(params, user: user, org: org) }

    it 'consumes and deletes the code' do
      data = described_class.consume_authorization_code(code)

      expect(data).to be_present
      expect(Mcp::Auth::AuthorizationCode.find_by(code: code)).to be_nil
    end

    it 'returns code data' do
      data = described_class.consume_authorization_code(code)

      expect(data[:client_id]).to eq(oauth_client.client_id)
      expect(data[:user_id]).to eq(user.id)
    end

    it 'returns nil for non-existent code' do
      data = described_class.consume_authorization_code('invalid-code')
      expect(data).to be_nil
    end
  end

  describe '.validate_pkce?' do
    let(:verifier) { 'test_verifier' }
    let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }

    it 'validates correct PKCE pair' do
      result = described_class.validate_pkce?(challenge, verifier)
      expect(result).to be true
    end

    it 'rejects incorrect verifier' do
      result = described_class.validate_pkce?(challenge, 'wrong_verifier')
      expect(result).to be false
    end

    it 'rejects blank verifier' do
      result = described_class.validate_pkce?(challenge, '')
      expect(result).to be false
    end

    it 'rejects blank challenge' do
      result = described_class.validate_pkce?('', verifier)
      expect(result).to be false
    end
  end
end
