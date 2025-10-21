# frozen_string_literal: true

require_relative "lib/mcp/auth/version"

Gem::Specification.new do |spec|
  # Required fields
  spec.name        = "mcp-auth"
  spec.version     = Mcp::Auth::VERSION
  spec.authors     = ["Serhii Borozenets"]
  spec.email       = ["serhii.borozenets@example.com"]
  spec.summary     = "OAuth 2.1 authorization for MCP servers"
  spec.description = "OAuth 2.1 authorization for Model Context Protocol (MCP) servers in Rails applications. Implements RFC 7591, 7636, 8414, 8707, 9728 with PKCE, dynamic client registration, and token management."
  spec.homepage    = "https://github.com/SerhiiBorozenets/mcp-auth"
  spec.license     = "MIT"

  # Required Ruby version
  spec.required_ruby_version = ">= 3.0.0"

  # Metadata for RubyGems.org
  spec.metadata = {
    "homepage_uri"      => spec.homepage,
    "changelog_uri"     => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri"   => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"  # Enable 2FA requirement
  }

  # Files to include in the gem
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir[
      "{app,config,db,lib}/**/*",
      "LICENSE.txt",
      "Rakefile",
      "README.md",
      "CHANGELOG.md",
      "CONTRIBUTING.md"
    ]
  end

  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "rails", ">= 7.0", "< 9.0"
  spec.add_dependency "jwt", ">= 1.0", "< 4.0"

  # Development dependencies
  spec.add_development_dependency "rspec-rails", "~> 6.0"
  spec.add_development_dependency "factory_bot_rails", "~> 6.4"
  spec.add_development_dependency "faker", "~> 3.0"
  spec.add_development_dependency "database_cleaner-active_record", "~> 2.0"
  spec.add_development_dependency "sqlite3", "~> 2.1"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "shoulda-matchers", "~> 6.0"
  spec.add_development_dependency "rubocop", "~> 1.50"
  spec.add_development_dependency "rubocop-rails", "~> 2.0"
  spec.add_development_dependency "rubocop-rspec", "~> 2.0"
end
