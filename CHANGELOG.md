# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-25

### Added
- **RFC 9207** — `iss` parameter on authorization-error redirects (success
  redirects already included it). Becomes a MUST in the MCP 2026-07-28
  spec release candidate.
- **RFC 7009** — `POST /oauth/revoke` now requires client authentication
  (HTTP Basic or form body) and only revokes tokens owned by the
  authenticated client. Honors the optional `token_type_hint` parameter.
- **RFC 7662** — `POST /oauth/introspect` now requires client
  authentication. Tokens not owned by the authenticated client are
  reported as `{active: false}` to prevent token-scanning attacks.
- Spec coverage for `revoke` + `introspect` endpoints (13 examples).

### Changed
- `revoke` and `introspect` now return HTTP 401 with
  `{error: "invalid_client"}` when client authentication fails. Previously
  they accepted unauthenticated requests. **This is a breaking change for
  callers that did not authenticate** — update clients to send credentials
  via HTTP Basic auth (preferred) or `client_id` + `client_secret` form
  params.
- `render_error` now accepts a `status:` keyword argument
  (default `:bad_request`).

## [0.1.0] - 2025-01-10

### Added
- Initial release of MCP Auth gem
- OAuth 2.1 authorization flow implementation
- PKCE support (RFC 7636) with S256 method requirement
- Dynamic Client Registration (RFC 7591)
- Token Revocation (RFC 7009)
- Token Introspection (RFC 7662)
- Authorization Server Metadata (RFC 8414)
- Protected Resource Metadata (RFC 9728)
- Resource Indicators support (RFC 8707) for token audience binding
- OpenID Connect Discovery support
- Automatic middleware for protecting `/mcp/*` routes
- JWT access tokens with proper audience validation
- Refresh token rotation for enhanced security
- Database-backed token storage for revocation support
- Customizable user data fetching
- Rake tasks for token cleanup and management
- Beautiful consent screen UI
- Comprehensive test suite
- Full documentation and examples

### Security
- HTTPS enforcement for production environments
- Secure token generation using SecureRandom
- Constant-time string comparison for PKCE validation
- Short-lived access tokens (1 hour default)
- Automatic refresh token rotation
- Token audience validation to prevent confused deputy attacks
- WWW-Authenticate header with resource metadata on 401 responses

[Unreleased]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SerhiiBorozenets/mcp-auth/releases/tag/v0.1.0