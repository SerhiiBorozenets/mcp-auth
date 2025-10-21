# Testing Your MCP OAuth Implementation

## Using MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) is an official tool for testing and debugging MCP servers with OAuth authentication. It's the easiest way to verify your OAuth setup before connecting ChatGPT or Claude.

### Installation

No installation needed! Use npx to run it directly:

```bash
npx @modelcontextprotocol/inspector
```

The inspector will open in your browser at `http://localhost:6274`.

### Step 1: Configure Your Server URL

1. **Transport Type**: Select `SSE` (Server-Sent Events)
2. **URL**: Enter your MCP server URL with OAuth:
   ```
   https://your-server.com/mcp/sse
   ```
   Or for local development with ngrok:
   ```
   https://your-subdomain.ngrok.dev/mcp/sse
   ```
3. **Connection Type**: Select `Via Proxy`

### Step 2: Configure OAuth Authentication

1. Click **"Open Auth Settings"** or expand the **"Authentication"** section
2. You'll see the OAuth Flow Progress with these steps:
    - ✅ Metadata Discovery
    - ✅ Client Registration
    - ⏳ Authorization Flow
    - ⏳ Token Exchange

### Step 3: Complete OAuth Flow

#### Option 1: Quick OAuth Flow (Recommended)

1. Click **"Quick OAuth Flow"** button
2. The inspector will:
    - Discover your `.well-known` endpoints
    - Register as an OAuth client
    - Open your authorization URL in a new window
    - Wait for the authorization callback

3. In the authorization window:
    - Log in to your application (if not already logged in)
    - Review and approve the requested scopes
    - You'll be redirected back automatically

4. The inspector will exchange the authorization code for tokens

#### Option 2: Guided OAuth Flow (Step by Step)

1. Click **"Guided OAuth Flow"** for manual step-by-step process
2. Follow the on-screen instructions for each step

### Step 4: Verify Connection

Once OAuth is complete, you should see:
- ✅ All steps in OAuth Flow Progress are checked
- The **"Connect"** button is enabled
- Status shows "Connected" after clicking Connect

### Step 5: Test Your MCP Tools

1. After connecting, you'll see a list of available tools in the History panel
2. Click on any tool to test it
3. The inspector will send the request with your OAuth token
4. View the response in the panel

## Common Issues and Solutions

### Issue 1: "Metadata Discovery Failed"

**Symptoms:**
- First step in OAuth Flow fails
- Error: "Failed to discover OAuth metadata"

**Fix:**
1. Verify your `.well-known` endpoints are accessible:
   ```bash
   curl https://your-server.com/.well-known/oauth-protected-resource
   curl https://your-server.com/.well-known/oauth-authorization-server
   ```

2. Check that both return valid JSON with:
    - `scopes_supported`: Should list your registered scopes
    - `authorization_servers`: Should point to your server
    - `authorization_endpoint`, `token_endpoint`, etc.

3. Ensure CORS headers are set correctly (already handled by the gem)

### Issue 2: "Client Registration Failed"

**Symptoms:**
- Second step fails
- Error in browser console or inspector

**Fix:**
1. Check that `/oauth/register` endpoint is accessible:
   ```bash
   curl -X POST https://your-server.com/oauth/register \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "MCP Inspector",
       "redirect_uris": ["http://localhost:6274/oauth/callback"]
     }'
   ```

2. Should return client credentials:
   ```json
   {
     "client_id": "...",
     "client_secret": "...",
     "redirect_uris": ["http://localhost:6274/oauth/callback"]
   }
   ```

### Issue 3: "Authorization Failed" or "Not all permissions granted"

**Symptoms:**
- Authorization window opens but returns an error
- Error: "Not all requested permissions were granted"

**Fix:**
1. Check Rails logs for what scopes are being requested:
   ```bash
   tail -f log/development.log | grep -E "(OAuth|scope)"
   ```

2. Ensure all requested scopes are registered in `config/initializers/mcp_auth.rb`:
   ```ruby
   config.register_scope 'mcp:read', name: '...', description: '...'
   config.register_scope 'mcp:write', name: '...', description: '...'
   config.register_scope 'mcp:tools', name: '...', description: '...'
   # Add any other scopes that appear in logs
   ```

3. Restart your server after adding scopes:
   ```bash
   spring stop
   rails server
   ```

### Issue 4: "Token Exchange Failed"

**Symptoms:**
- Authorization succeeds but token exchange fails
- 401 or 400 error during token exchange

**Fix:**
1. Check that PKCE is properly configured (already handled by the gem)
2. Verify token endpoint is accessible:
   ```bash
   curl -X POST https://your-server.com/oauth/token \
     -d "grant_type=authorization_code" \
     -d "code=TEST_CODE" \
     -d "redirect_uri=http://localhost:6274/oauth/callback" \
     -d "code_verifier=TEST_VERIFIER"
   ```

3. Check Rails logs for PKCE validation errors

### Issue 5: Connection Drops or Tools Don't Work

**Symptoms:**
- OAuth completes but connection fails
- Tools return 401 errors

**Fix:**
1. Verify your MCP server path matches the OAuth configuration:
   ```ruby
   # config/initializers/mcp_auth.rb
   config.mcp_server_path = '/mcp'  # Must match your FastMCP mount
   ```

2. Check that tokens are being validated correctly:
   ```bash
   # In Rails logs, look for:
   [TokenService] Token validation failed
   [TokenService] Token audience mismatch
   ```

3. Ensure your MCP server is actually mounted at the configured path

## Testing Checklist

Use this checklist to verify your OAuth setup:

- [ ] **Discovery endpoints work**
  ```bash
  curl https://your-server.com/.well-known/oauth-protected-resource | jq
  curl https://your-server.com/.well-known/oauth-authorization-server | jq
  ```

- [ ] **Scopes are registered and advertised**
  ```bash
  curl https://your-server.com/.well-known/oauth-authorization-server | jq .scopes_supported
  # Should show: ["mcp:read", "mcp:write", ...]
  ```

- [ ] **Client registration works**
  ```bash
  curl -X POST https://your-server.com/oauth/register \
    -H "Content-Type: application/json" \
    -d '{"client_name":"Test","redirect_uris":["http://localhost:6274/oauth/callback"]}'
  ```

- [ ] **Authorization endpoint is accessible**
    - Visit in browser: `https://your-server.com/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:6274/oauth/callback&code_challenge=test&code_challenge_method=S256`
    - Should redirect to login or show consent screen

- [ ] **MCP Inspector connects successfully**
    - All OAuth flow steps complete
    - Tools are visible and callable
    - Responses include proper data

- [ ] **Rails logs show successful authentication**
  ```bash
  tail -f log/development.log | grep -E "(OAuth|TokenService|WellKnown)"
  ```

## Advanced Testing: Manual OAuth Flow

For debugging, you can manually test the OAuth flow:

### 1. Discover Endpoints

```bash
curl https://your-server.com/.well-known/oauth-protected-resource | jq
```

### 2. Register a Test Client

```bash
curl -X POST https://your-server.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Manual Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }' | jq

# Save the client_id and client_secret from response
```

### 3. Generate PKCE Values

```bash
# Generate code verifier (43-128 characters)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
echo "Code Verifier: $CODE_VERIFIER"

# Generate code challenge (SHA256 hash of verifier, base64url encoded)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | openssl base64 | tr -d "=" | tr "+/" "-_")
echo "Code Challenge: $CODE_CHALLENGE"
```

### 4. Start Authorization Flow

Open in browser (replace YOUR_CLIENT_ID):
```
https://your-server.com/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=mcp:read%20mcp:write&state=random_state&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

### 5. Exchange Code for Token

After authorization, extract the `code` from the redirect URL and exchange it:

```bash
curl -X POST https://your-server.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=$CODE_VERIFIER" \
  -d "client_id=YOUR_CLIENT_ID" | jq
```

### 6. Use Access Token

```bash
# Extract access_token from previous response
ACCESS_TOKEN="your_access_token_here"

# Test with your MCP server
curl https://your-server.com/mcp/sse \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Debugging with Rails Console

You can also test token generation and validation in Rails console:

```ruby
# Open Rails console
rails console

# Generate a test token
token_data = {
  client_id: 'test-client',
  scope: 'mcp:read mcp:write',
  user_id: User.first.id,
  org_id: nil,
  resource: 'https://your-server.com/mcp'
}

access_token = Mcp::Auth::Services::TokenService.generate_access_token(
  token_data,
  base_url: 'https://your-server.com'
)

puts "Access Token: #{access_token}"

# Validate the token
payload = Mcp::Auth::Services::TokenService.validate_access_token(
  access_token,
  resource: 'https://your-server.com/mcp'
)

puts "Token Payload: #{payload.inspect}"

# Check scopes
puts "Registered Scopes: #{Mcp::Auth::ScopeRegistry.available_scopes.keys.inspect}"
```

## Testing with Different MCP Clients

### ChatGPT

1. In ChatGPT, go to Settings → Connectors
2. Add a new connector with your server URL
3. Follow the OAuth flow
4. Test by asking ChatGPT to use your MCP tools

### Claude Desktop

1. Edit your Claude config file:
    - Mac: `~/Library/Application Support/Claude/claude_desktop_config.json`
    - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. Add your MCP server:
   ```json
   {
     "mcpServers": {
       "your-server": {
         "url": "https://your-server.com/mcp/sse",
         "oauth": {
           "clientId": "your-client-id",
           "clientSecret": "your-client-secret"
         }
       }
     }
   }
   ```

3. Restart Claude Desktop
4. Claude will prompt for authorization on first use

## Continuous Testing

For ongoing development, set up automated testing:

```ruby
# spec/requests/oauth_flow_spec.rb
RSpec.describe "OAuth Flow", type: :request do
  it "completes full OAuth flow" do
    # 1. Discover metadata
    get '/.well-known/oauth-protected-resource'
    expect(response).to have_http_status(:ok)
    metadata = JSON.parse(response.body)
    expect(metadata['scopes_supported']).to include('mcp:read')
    
    # 2. Register client
    post '/oauth/register', params: {
      client_name: 'Test Client',
      redirect_uris: ['http://localhost:3000/callback']
    }.to_json, headers: { 'Content-Type': 'application/json' }
    
    expect(response).to have_http_status(:ok)
    client_data = JSON.parse(response.body)
    
    # 3. Test authorization endpoint
    get '/oauth/authorize', params: {
      response_type: 'code',
      client_id: client_data['client_id'],
      redirect_uri: 'http://localhost:3000/callback',
      code_challenge: 'test_challenge',
      code_challenge_method: 'S256'
    }
    
    expect(response).to have_http_status(:redirect)
  end
end
```

## Getting Help

If you're still having issues:

1. **Enable debug logging**:
   ```ruby
   # config/environments/development.rb
   config.log_level = :debug
   ```

2. **Check all logs**:
   ```bash
   tail -f log/development.log
   ```

3. **Use the diagnostic tasks**:
   ```bash
   rails mcp_auth:scopes
   rails mcp_auth:diagnose_path
   rails mcp_auth:test_chatgpt_scopes
   ```

4. **Share relevant information** when asking for help:
    - MCP Inspector screenshot showing where it fails
    - Rails log excerpts showing OAuth requests
    - Your `.well-known` endpoint responses
    - List of registered scopes

## Resources

- [MCP Inspector GitHub](https://github.com/modelcontextprotocol/inspector)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)