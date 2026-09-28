# frozen_string_literal: true

require 'rails/generators'
require 'rails/generators/active_record'

module Mcp
  module Auth
    module Generators
      # Step 2 of upgrading an existing install: copies the data migration that
      # hashes secrets already stored in plaintext (client secrets, tokens, codes)
      # to sha256$ digests, in place. Run it only after EVERY server runs a
      # version that reads hashed rows (>= 0.6.0): older versions look secrets
      # up by their plaintext and would reject every client and token.
      # Irreversible. Safe to re-run the generator (an existing migration is
      # skipped) and the migration (already-hashed rows are left alone).
      #
      #   rails generate mcp:auth:hash_secrets
      #   rails db:migrate
      class HashSecretsGenerator < Rails::Generators::Base
        include ActiveRecord::Generators::Migration

        source_root File.expand_path('templates', __dir__)

        desc 'Adds the migration that hashes existing MCP Auth secrets at rest (run after every server is upgraded).'

        def copy_hash_migration
          migration_template 'hash_mcp_auth_secrets_at_rest.rb.erb',
                             'db/migrate/hash_mcp_auth_secrets_at_rest.rb',
                             migration_version: migration_version
        end

        def show_post_install_message
          say "\nMCP Auth secrets-hashing migration added.", :green
          say 'Only run it once NO server runs mcp-auth <= 0.5.0 (they cannot read hashed rows):'
          say '  rails db:migrate'
          say 'Irreversible: afterwards, rolling back to <= 0.5.0 signs every client out.'
          say 'Then harden: config.secret_dual_read = false in config/initializers/mcp_auth.rb'
        end

        private

        def migration_version
          "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
        end
      end
    end
  end
end
