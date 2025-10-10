# frozen_string_literal: true

namespace :mcp_auth do
  desc "Clean up expired tokens and authorization codes"
  task cleanup: :environment do
    puts "Cleaning up expired MCP Auth tokens..."

    expired_auth_codes = Mcp::Auth::AuthorizationCode.cleanup_expired
    puts "  - Removed #{expired_auth_codes} expired authorization codes"

    expired_access_tokens = Mcp::Auth::AccessToken.cleanup_expired
    puts "  - Removed #{expired_access_tokens} expired access tokens"

    expired_refresh_tokens = Mcp::Auth::RefreshToken.cleanup_expired
    puts "  - Removed #{expired_refresh_tokens} expired refresh tokens"

    puts "Cleanup complete!"
  end

  desc "Show MCP Auth statistics"
  task stats: :environment do
    puts "\nMCP Auth Statistics"
    puts "=" * 50

    puts "\nOAuth Clients:"
    puts "  Total: #{Mcp::Auth::OauthClient.count}"

    puts "\nAuthorization Codes:"
    puts "  Active: #{Mcp::Auth::AuthorizationCode.active.count}"
    puts "  Expired: #{Mcp::Auth::AuthorizationCode.expired.count}"
    puts "  Total: #{Mcp::Auth::AuthorizationCode.count}"

    puts "\nAccess Tokens:"
    puts "  Active: #{Mcp::Auth::AccessToken.active.count}"
    puts "  Expired: #{Mcp::Auth::AccessToken.expired.count}"
    puts "  Total: #{Mcp::Auth::AccessToken.count}"

    puts "\nRefresh Tokens:"
    puts "  Active: #{Mcp::Auth::RefreshToken.active.count}"
    puts "  Expired: #{Mcp::Auth::RefreshToken.expired.count}"
    puts "  Total: #{Mcp::Auth::RefreshToken.count}"

    puts "\n" + "=" * 50
  end

  desc "Revoke all tokens for a specific client"
  task :revoke_client_tokens, [:client_id] => :environment do |_t, args|
    client_id = args[:client_id]

    if client_id.blank?
      puts "Error: Please provide a client_id"
      puts "Usage: rake mcp_auth:revoke_client_tokens[CLIENT_ID]"
      exit 1
    end

    puts "Revoking all tokens for client: #{client_id}"

    auth_codes = Mcp::Auth::AuthorizationCode.where(client_id: client_id).delete_all
    access_tokens = Mcp::Auth::AccessToken.where(client_id: client_id).delete_all
    refresh_tokens = Mcp::Auth::RefreshToken.where(client_id: client_id).delete_all

    puts "  - Removed #{auth_codes} authorization codes"
    puts "  - Removed #{access_tokens} access tokens"
    puts "  - Removed #{refresh_tokens} refresh tokens"
    puts "Complete!"
  end

  desc "Revoke all tokens for a specific user"
  task :revoke_user_tokens, [:user_id] => :environment do |_t, args|
    user_id = args[:user_id]

    if user_id.blank?
      puts "Error: Please provide a user_id"
      puts "Usage: rake mcp_auth:revoke_user_tokens[USER_ID]"
      exit 1
    end

    puts "Revoking all tokens for user: #{user_id}"

    auth_codes = Mcp::Auth::AuthorizationCode.where(user_id: user_id).delete_all
    access_tokens = Mcp::Auth::AccessToken.where(user_id: user_id).delete_all
    refresh_tokens = Mcp::Auth::RefreshToken.where(user_id: user_id).delete_all

    puts "  - Removed #{auth_codes} authorization codes"
    puts "  - Removed #{access_tokens} access tokens"
    puts "  - Removed #{refresh_tokens} refresh tokens"
    puts "Complete!"
  end
end
