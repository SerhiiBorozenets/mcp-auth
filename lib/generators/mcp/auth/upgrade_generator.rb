# frozen_string_literal: true

require 'rails/generators'
require 'rails/generators/active_record'

module Mcp
  module Auth
    module Generators
      # Copies pending migrations for an EXISTING install without touching the
      # initializer or views (unlike the full install generator, which would
      # prompt to overwrite them). Safe to re-run: `migration_template` skips a
      # migration whose class already exists.
      #
      #   rails generate mcp:auth:upgrade
      #   rails db:migrate
      class UpgradeGenerator < Rails::Generators::Base
        include ActiveRecord::Generators::Migration

        source_root File.expand_path('templates', __dir__)

        desc 'Adds pending MCP Auth migrations for an existing install (no initializer/view changes).'

        def copy_pending_migrations
          migration_template 'hash_mcp_auth_secrets_at_rest.rb.erb',
                             'db/migrate/hash_mcp_auth_secrets_at_rest.rb',
                             migration_version: migration_version
        end

        def show_post_install_message
          say "\nMCP Auth upgrade migration added.", :green
          say 'Next steps:'
          say '  1. Deploy this gem version and run migrations together:'
          say '       rails db:migrate   # backfills existing secrets to sha256$ digests, in place'
          say '  2. Once every row is hashed and no old app code remains, harden by'
          say '     disabling the transitional dual-read in config/initializers/mcp_auth.rb:'
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
