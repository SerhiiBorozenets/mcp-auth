# frozen_string_literal: true

require 'rails/generators'
require 'rails/generators/active_record'

module Mcp
  module Auth
    module Generators
      class InstallGenerator < Rails::Generators::Base
        include ActiveRecord::Generators::Migration

        source_root File.expand_path('templates', __dir__)

        desc "Generates MCP Auth migrations, initializer, and views"

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

        def copy_views
          # Create the directory first
          empty_directory "app/views/mcp/auth"

          # Copy consent view template
          template "views/consent.html.erb", "app/views/mcp/auth/consent.html.erb"
        end

        def show_readme
          if File.exist?(File.join(self.class.source_root, "README"))
            readme "README"
          end
        rescue Thor::Error
          # Skip silently
        end

        def show_post_install_message
          say "\n" + "="*80
          say "MCP Auth has been installed!", :green
          say "="*80
          say "\nFiles created:"
          say "  - db/migrate/*_create_mcp_auth_*.rb (4 migrations)"
          say "  - config/initializers/mcp_auth.rb"
          say "  - app/views/mcp/auth/consent.html.erb"
          say "\nNext steps:"
          say "1. Run migrations: rails db:migrate"
          say "2. Configure: config/initializers/mcp_auth.rb"
          say "3. Customize consent view: app/views/mcp/auth/consent.html.erb"
          say "4. Mount routes in config/routes.rb (if not already done):"
          say "   mount Mcp::Auth::Engine => '/'"
          say "\nDocumentation: https://github.com/SerhiiBorozenets/mcp-auth"
          say "="*80 + "\n"
        end

        private

        def migration_version
          "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
        end
      end
    end
  end
end
