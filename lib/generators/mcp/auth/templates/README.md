===============================================================================

MCP Auth has been installed!

Next steps:

1. Run the migrations:

   rails db:migrate

2. Configure the initializer at config/initializers/mcp_auth.rb

   Set your OAuth secret and customize user data fetching.

3. Ensure your ApplicationController has authentication methods:

    - current_user: returns the currently signed-in user
    - current_org: returns the current organization (optional)
    - user_signed_in?: returns true if user is signed in

4. Set environment variables (optional):

   MCP_OAUTH_PRIVATE_KEY: Secret key for signing JWTs
   MCP_AUTHORIZATION_SERVER_URL: Custom authorization server URL

5. Your OAuth endpoints are now available at:

    - /.well-known/oauth-protected-resource (Protected Resource Metadata)
    - /.well-known/oauth-authorization-server (Authorization Server Metadata)
    - /oauth/authorize (Authorization endpoint)
    - /oauth/token (Token endpoint)
    - /oauth/register (Dynamic client registration)
    - /oauth/revoke (Token revocation)
    - /oauth/introspect (Token introspection)

For more information, see: https://github.com/yourusername/mcp-auth

===============================================================================