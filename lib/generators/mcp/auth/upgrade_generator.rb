# frozen_string_literal: true

require 'rails/generators'
require 'rails/generators/active_record'

module Mcp
  module Auth
    module Generators
      # Step 1 of upgrading an EXISTING install: copies the additive schema
      # migration (new columns only) without touching the initializer or views
      # (unlike the full install generator, which would prompt to overwrite them).
      # Safe to re-run: `migration_template` skips a migration whose class already
      # exists.
      #
      # The columns are purely additive, so older gem versions keep working with
      # them. Run this migration BEFORE (or as part of) deploying the new version:
      # the new code needs the columns and answers every OAuth endpoint with a 500
      # until they exist. Hashing existing secrets is a separate, later step
      # (`rails generate mcp:auth:hash_secrets`), because older versions cannot
      # read hashed rows.
      #
      #   rails generate mcp:auth:upgrade
      #   rails db:migrate
      class UpgradeGenerator < Rails::Generators::Base
        include ActiveRecord::Generators::Migration

        source_root File.expand_path('templates', __dir__)

        desc 'Adds pending MCP Auth schema migrations for an existing install (no initializer/view changes).'

        def copy_pending_migrations
          migration_template 'add_mcp_auth_confidential_client_and_reuse.rb.erb',
                             'db/migrate/add_mcp_auth_confidential_client_and_reuse.rb',
                             migration_version: migration_version
        end

        def show_post_install_message
          say "\nMCP Auth upgrade migration added (new columns only).", :green
          say 'Next steps:'
          say '  1. Run it BEFORE the new gem version serves traffic (e.g. in your release'
          say '     phase). The columns are additive, so servers still on the old version'
          say '     keep working:'
          say '       rails db:migrate'
          say '  2. Deploy this gem version to every server. If you sign with HS256, set a'
          say '     dedicated MCP_HMAC_SECRET first (not secret_key_base).'
          say '  3. Once NO server runs the old version, hash existing secrets at rest:'
          say '       rails generate mcp:auth:hash_secrets && rails db:migrate'
          say '  4. Then disable the transitional dual-read in config/initializers/mcp_auth.rb:'
          say '       config.secret_dual_read = false'
        end

        private

        def migration_version
          "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
        end
      end
    end
  end
end
