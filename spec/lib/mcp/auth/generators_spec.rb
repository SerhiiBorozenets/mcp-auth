# frozen_string_literal: true

require 'rails_helper'
require 'tmpdir'
require 'generators/mcp/auth/install_generator'
require 'generators/mcp/auth/upgrade_generator'
require 'generators/mcp/auth/hash_secrets_generator'

RSpec.describe 'mcp-auth generators' do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  def run_generator(klass)
    capture_quietly { klass.start([], destination_root: @dir) }
    Dir[File.join(@dir, 'db/migrate/*.rb')].map { |f| File.basename(f).sub(/\A\d+_/, '') }
  end

  def capture_quietly
    original = $stdout
    $stdout = StringIO.new
    yield
  ensure
    $stdout = original
  end

  it 'upgrade copies ONLY the additive schema migration (safe to run before deploying)' do
    expect(run_generator(Mcp::Auth::Generators::UpgradeGenerator))
      .to contain_exactly('add_mcp_auth_confidential_client_and_reuse.rb')
  end

  it 'hash_secrets copies ONLY the backfill (run once every server is upgraded)' do
    expect(run_generator(Mcp::Auth::Generators::HashSecretsGenerator))
      .to contain_exactly('hash_mcp_auth_secrets_at_rest.rb')
  end

  it 'upgrade is idempotent' do
    run_generator(Mcp::Auth::Generators::UpgradeGenerator)

    expect(run_generator(Mcp::Auth::Generators::UpgradeGenerator).size).to eq(1)
  end
end
