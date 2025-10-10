# frozen_string_literal: true

Mcp::Auth::Engine.routes.draw do
  # RFC 9728: OAuth 2.0 Protected Resource Metadata
  match '/.well-known/oauth-protected-resource',
        to: 'well_known#protected_resource',
        via: %i[get options]

  match '/.well-known/oauth-protected-resource/*path',
        to: 'well_known#protected_resource',
        via: %i[get options]

  # RFC 8414: OAuth 2.0 Authorization Server Metadata
  match '/.well-known/oauth-authorization-server',
        to: 'well_known#authorization_server',
        via: %i[get options]

  # OpenID Connect Discovery
  match '/.well-known/openid-configuration',
        to: 'well_known#openid_configuration',
        via: %i[get options]

  match '/.well-known/jwks.json',
        to: 'well_known#jwks',
        via: %i[get options]

  # OAuth 2.1 endpoints
  match '/oauth/authorize', to: 'oauth#authorize', via: %i[get post options]
  post '/oauth/approve', to: 'oauth#approve'
  match '/oauth/token', to: 'oauth#token', via: %i[post options]

  # RFC 7591: Dynamic Client Registration
  match '/oauth/register', to: 'oauth#register', via: %i[post options]

  # RFC 7009: Token Revocation
  match '/oauth/revoke', to: 'oauth#revoke', via: %i[post options]

  # RFC 7662: Token Introspection
  match '/oauth/introspect', to: 'oauth#introspect', via: %i[post options]

  # OpenID Connect UserInfo
  match '/oauth/userinfo', to: 'oauth#userinfo', via: %i[get options]
end
