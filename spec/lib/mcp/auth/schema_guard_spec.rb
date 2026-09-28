# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::SchemaGuard do
  describe '.missing_columns' do
    it 'is empty when the schema is up to date' do
      expect(described_class.missing_columns).to eq([])
    end

    it 'reports a column the code needs but the table lacks' do
      allow(Mcp::Auth::OauthClient).to receive(:column_names)
        .and_return(Mcp::Auth::OauthClient.column_names - ['token_endpoint_auth_method'])

      expect(described_class.missing_columns)
        .to include('mcp_auth_oauth_clients.token_endpoint_auth_method')
    end

    it 'returns [] (never raises) when the database is unavailable' do
      allow(Mcp::Auth::OauthClient).to receive(:table_exists?).and_raise('no database')

      expect(described_class.missing_columns).to eq([])
    end
  end

  describe '.check!' do
    it 'returns true when the schema is current' do
      expect(described_class.check!).to be true
    end

    it 'raises PendingMigrationError naming the fix when a column is missing' do
      allow(Mcp::Auth::RefreshToken).to receive(:column_names)
        .and_return(Mcp::Auth::RefreshToken.column_names - ['revoked_at'])

      expect { described_class.check! }
        .to raise_error(Mcp::Auth::PendingMigrationError, /rails db:migrate/)
    end
  end
end
