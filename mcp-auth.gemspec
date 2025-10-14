# frozen_string_literal: true

require_relative "lib/mcp/auth/version"

Gem::Specification.new do |spec|
  spec.name        = "mcp-auth"
  spec.version     = Mcp::Auth::VERSION
  spec.authors     = ["Serhii Borozenets"]
  spec.email       = ["your.email@example.com"]
  spec.homepage    = "https://github.com/SerhiiBorozenets/mcp-auth"
  spec.summary     = "OAuth 2.1 authorization for MCP servers"
  spec.description = "OAuth 2.1 authorization for Model Context Protocol (MCP) servers in Rails applications"
  spec.license     = "MIT"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir[
    "{app,config,db,lib}/**/*",
    "LICENSE.txt",
    "Rakefile",
    "README.md",
    "CHANGELOG.md"
  ]

  spec.require_paths = ["lib"]

  spec.add_dependency "rails", ">= 7.0"
  spec.add_dependency "jwt", ">= 3.0"

  spec.add_development_dependency "rspec-rails", "~> 6.0"
  spec.add_development_dependency "factory_bot_rails", "~> 6.4"
  spec.add_development_dependency "faker", "~> 3.0"
  spec.add_development_dependency "database_cleaner-active_record", "~> 2.0"
  spec.add_development_dependency "sqlite3", "~> 2.1"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "shoulda-matchers", "~> 6.0"
end
