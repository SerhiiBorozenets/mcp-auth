# frozen_string_literal: true

require 'rails/generators'
require 'rails/generators/active_record'

module Mcp
  module Auth
    module Generators
      class InstallGenerator < Rails::Generators::Base
        include ActiveRecord::Generators::Migration

        source_root File.expand_path('templates', __dir__)

        desc "Generates MCP Auth migrations and initializer"

        def copy_migrations
          migration_template "create_oauth_clients.rb.erb",
                             "db/migrate/create_mcp_auth_oauth_clients.rb",
                             migration_version: migration_version

          migration_template "create_authorization_codes.rb.erb",
                             "db/migrate/create_mcp_auth_authorization_codes.rb",
                             migration_version: migration_version

          migration_template "create_access_tokens.rb.erb",
                             "db/migrate/create_mcp_auth_access_tokens.rb",
                             migration_version: migration_version

          migration_template "create_refresh_tokens.rb.erb",
                             "db/migrate/create_mcp_auth_refresh_tokens.rb",
                             migration_version: migration_version
        end

        def copy_initializer
          template "initializer.rb", "config/initializers/mcp_auth.rb"
        end

        def show_readme
          readme "README" if behavior == :invoke
        end

        private

        def migration_version
          "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
        end
      end
    end
  end
end
