# frozen_string_literal: true

require_relative "lib/mcp/auth/version"

Gem::Specification.new do |spec|
  spec.name = "mcp-auth"
  spec.version = Mcp::Auth::VERSION
  spec.authors = ["Your Name"]
  spec.email = ["your.email@example.com"]

  spec.summary = "OAuth 2.1 authorization for Model Context Protocol servers"
  spec.description = "A Rails engine providing OAuth 2.1 authorization for MCP servers with PKCE, dynamic client registration, and resource indicators support"
  spec.homepage = "https://github.com/yourusername/mcp-auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end

  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Runtime dependencies
  spec.add_dependency "rails", ">= 7.0"
  spec.add_dependency "jwt", "~> 2.7"

  # Development dependencies
  spec.add_development_dependency "rspec-rails", "~> 6.0"
  spec.add_development_dependency "factory_bot_rails", "~> 6.2"
  spec.add_development_dependency "faker", "~> 3.2"
  spec.add_development_dependency "rubocop", "~> 1.50"
  spec.add_development_dependency "rubocop-rails", "~> 2.19"
  spec.add_development_dependency "rubocop-rspec", "~> 2.20"
end
