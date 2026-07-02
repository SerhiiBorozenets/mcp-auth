# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::OauthController, type: :controller do
  routes { Mcp::Auth::Engine.routes }

  let(:client) { create(:oauth_client) }
  let(:other_client) { create(:oauth_client) }
  let(:basic_auth) do
    encoded = Base64.strict_encode64("#{client.client_id}:#{client.client_secret}")
    "Basic #{encoded}"
  end

  describe 'POST #revoke (RFC 7009)' do
    let!(:access_token) { create(:access_token, oauth_client: client) }
    let!(:refresh_token) { create(:refresh_token, oauth_client: client) }

    context 'without client authentication' do
      it 'returns 401' do
        post :revoke, params: { token: access_token.token }

        expect(response).to have_http_status(:unauthorized)
        expect(JSON.parse(response.body)['error']).to eq('invalid_client')
      end
    end

    context 'with valid client credentials via Basic auth' do
      before { request.headers['Authorization'] = basic_auth }

      it 'revokes an access token owned by the client' do
        post :revoke, params: { token: access_token.token }

        expect(response).to have_http_status(:ok)
        expect(Mcp::Auth::AccessToken.find_by(id: access_token.id)).to be_nil
      end

      it 'revokes a refresh token owned by the client' do
        post :revoke, params: { token: refresh_token.token }

        expect(response).to have_http_status(:ok)
        expect(Mcp::Auth::RefreshToken.find_by(id: refresh_token.id)).to be_nil
      end

      it 'returns 200 but does not revoke an unknown token (RFC 7009 §2.2)' do
        post :revoke, params: { token: 'never-issued' }

        expect(response).to have_http_status(:ok)
      end

      it 'returns 200 but does not revoke a token owned by another client' do
        foreign_token = create(:access_token, oauth_client: other_client)

        post :revoke, params: { token: foreign_token.token }

        expect(response).to have_http_status(:ok)
        expect(Mcp::Auth::AccessToken.find_by(id: foreign_token.id)).to be_present
      end

      it 'returns 400 when token parameter is missing' do
        post :revoke

        expect(response).to have_http_status(:bad_request)
      end
    end

    context 'with wrong client_secret' do
      before do
        encoded = Base64.strict_encode64("#{client.client_id}:wrong-secret")
        request.headers['Authorization'] = "Basic #{encoded}"
      end

      it 'returns 401' do
        post :revoke, params: { token: access_token.token }

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with credentials in form params instead of Basic auth' do
      it 'accepts client_id + client_secret in the body' do
        post :revoke, params: {
          token: access_token.token,
          client_id: client.client_id,
          client_secret: client.client_secret
        }

        expect(response).to have_http_status(:ok)
        expect(Mcp::Auth::AccessToken.find_by(id: access_token.id)).to be_nil
      end
    end
  end

  describe 'POST #introspect (RFC 7662)' do
    let!(:refresh_token) { create(:refresh_token, oauth_client: client) }

    context 'without client authentication' do
      it 'returns 401' do
        post :introspect, params: { token: refresh_token.token }

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with valid client authentication' do
      before { request.headers['Authorization'] = basic_auth }

      it 'returns active:false for unknown tokens' do
        post :introspect, params: { token: 'never-issued' }

        expect(response).to have_http_status(:ok)
        expect(JSON.parse(response.body)).to eq({ 'active' => false })
      end

      it 'returns active:false for blank token' do
        post :introspect

        expect(JSON.parse(response.body)).to eq({ 'active' => false })
      end

      it 'returns active:true with claims for a refresh token owned by the client' do
        post :introspect, params: { token: refresh_token.token }

        body = JSON.parse(response.body)
        expect(body['active']).to be true
        expect(body['client_id']).to eq(client.client_id)
      end

      it 'returns active:false for tokens owned by another client (anti-scanning)' do
        foreign_token = create(:refresh_token, oauth_client: other_client)

        post :introspect, params: { token: foreign_token.token }

        expect(JSON.parse(response.body)).to eq({ 'active' => false })
      end
    end
  end

  describe 'GET #authorize redirect_uri validation (RFC 6749 §3.1.2.3)' do
    let(:user) { create(:user) }
    let(:base_params) do
      {
        response_type: 'code',
        client_id: client.client_id,
        redirect_uri: 'http://localhost:3000/callback',
        code_challenge: 'challenge',
        code_challenge_method: 'S256',
        scope: 'mcp:read'
      }
    end

    it 'rejects an unregistered redirect_uri WITHOUT redirecting to it' do
      get :authorize, params: base_params.merge(redirect_uri: 'http://evil.example.com/cb')

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_request')
    end

    it 'rejects an unknown client_id' do
      get :authorize, params: base_params.merge(client_id: 'does-not-exist')

      expect(response).to have_http_status(:bad_request)
    end

    it 'never auto-issues a code from GET /authorize, even with approved=true (no consent bypass)' do
      allow(controller).to receive(:mcp_current_user).and_return(user)

      get :authorize, params: base_params.merge(approved: 'true')

      # The consent screen is rendered; a code is issued only via POST /approve.
      expect(response).to have_http_status(:ok)
      expect(response).not_to have_http_status(:redirect)
      expect(Mcp::Auth::AuthorizationCode.count).to eq(0)
    end

    it 'issues a code via the CSRF-protected POST /oauth/approve when the user approves' do
      allow(controller).to receive(:mcp_current_user).and_return(user)

      post :approve, params: base_params.merge(approved: 'true', scopes: ['mcp:read'])

      expect(response).to have_http_status(:redirect)
      expect(response.location).to start_with('http://localhost:3000/callback?')
      expect(response.location).to include('code=')
      expect(response.location).to include('iss=')
    end

    it 'rejects a resource indicator that does not identify this server (RFC 8707)' do
      allow(controller).to receive(:mcp_current_user).and_return(user)

      get :authorize, params: base_params.merge(resource: 'https://evil.example.com/mcp')

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_request')
      expect(Mcp::Auth::AuthorizationCode.count).to eq(0)
    end

    it 'does not grant scopes the client never requested (M2, least privilege)' do
      allow(controller).to receive(:mcp_current_user).and_return(user)

      post :approve, params: base_params.merge(
        approved: 'true', scope: 'mcp:read', scopes: %w[mcp:read mcp:write]
      )

      expect(response).to have_http_status(:redirect)
      expect(Mcp::Auth::AuthorizationCode.last.scope.split).to contain_exactly('mcp:read')
    end
  end

  describe 'POST #token authorization_code grant' do
    let(:user) { create(:user) }
    let(:verifier) { 'a' * 64 }
    let(:challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false) }
    let(:redirect_uri) { 'http://localhost:3000/callback' }
    let(:code) do
      Mcp::Auth::Services::AuthorizationService.generate_authorization_code(
        {
          client_id: client.client_id,
          redirect_uri: redirect_uri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          scope: 'mcp:read'
        },
        user: user,
        org: nil
      )
    end

    it 'issues tokens for the client the code was issued to' do
      post :token, params: {
        grant_type: 'authorization_code', code: code, code_verifier: verifier,
        redirect_uri: redirect_uri, client_id: client.client_id
      }

      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)['access_token']).to be_present
    end

    it 'rejects when the requesting client_id does not match the code (RFC 6749 §4.1.3)' do
      post :token, params: {
        grant_type: 'authorization_code', code: code, code_verifier: verifier,
        redirect_uri: redirect_uri, client_id: other_client.client_id
      }

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_grant')
    end

    it 'rejects a wrong PKCE verifier' do
      post :token, params: {
        grant_type: 'authorization_code', code: code, code_verifier: 'wrong',
        redirect_uri: redirect_uri, client_id: client.client_id
      }

      expect(JSON.parse(response.body)['error']).to eq('invalid_grant')
    end

    it 'rejects re-use of an authorization code (single-use, OAuth 2.1 §4.1.2)' do
      issued = code
      post :token, params: {
        grant_type: 'authorization_code', code: issued, code_verifier: verifier,
        redirect_uri: redirect_uri, client_id: client.client_id
      }
      expect(response).to have_http_status(:ok)

      post :token, params: {
        grant_type: 'authorization_code', code: issued, code_verifier: verifier,
        redirect_uri: redirect_uri, client_id: client.client_id
      }
      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_grant')
    end

    it 'issues no tokens when a racing request already consumed the code' do
      # Simulate losing the atomic consume race: the row was deleted by the
      # other request between our validate and our consume.
      allow(Mcp::Auth::Services::AuthorizationService)
        .to receive(:consume_authorization_code).and_return(nil)

      expect do
        post :token, params: {
          grant_type: 'authorization_code', code: code, code_verifier: verifier,
          redirect_uri: redirect_uri, client_id: client.client_id
        }
      end.not_to change(Mcp::Auth::AccessToken, :count)

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_grant')
    end
  end

  describe 'POST #token refresh_token grant' do
    let!(:refresh) { create(:refresh_token, oauth_client: client, scope: 'mcp:read mcp:write') }

    it 'narrows scope when a subset is requested (RFC 6749 §6)' do
      post :token, params: {
        grant_type: 'refresh_token', refresh_token: refresh.token,
        scope: 'mcp:read', client_id: client.client_id
      }

      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)['scope']).to eq('mcp:read')
    end

    it 'rotates the refresh token' do
      post :token, params: {
        grant_type: 'refresh_token', refresh_token: refresh.token, client_id: client.client_id
      }

      expect(Mcp::Auth::RefreshToken.find_by(id: refresh.id)).to be_nil
    end

    it 'rejects redemption by a client other than the one it was issued to (OAuth 2.1 §4.3.1)' do
      post :token, params: {
        grant_type: 'refresh_token', refresh_token: refresh.token, client_id: other_client.client_id
      }

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_grant')
      # The token is not rotated/consumed on a failed binding check.
      expect(Mcp::Auth::RefreshToken.find_by(id: refresh.id)).to be_present
    end

    it 'rejects a resource indicator that does not identify this server (RFC 8707)' do
      post :token, params: {
        grant_type: 'refresh_token', refresh_token: refresh.token,
        client_id: client.client_id, resource: 'https://evil.example.com/mcp'
      }

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_target')
    end

    it 'rejects a presented but invalid client_secret (H1)' do
      post :token, params: {
        grant_type: 'refresh_token', refresh_token: refresh.token,
        client_id: client.client_id, client_secret: 'wrong-secret'
      }

      expect(response).to have_http_status(:unauthorized)
      expect(JSON.parse(response.body)['error']).to eq('invalid_client')
      expect(Mcp::Auth::RefreshToken.find_by(id: refresh.id)).to be_present # not rotated
    end

    it 'accepts a presented valid client_secret' do
      post :token, params: {
        grant_type: 'refresh_token', refresh_token: refresh.token,
        client_id: client.client_id, client_secret: client.client_secret
      }

      expect(response).to have_http_status(:ok)
    end

    it 'issues no tokens when a racing request already rotated the token (M1)' do
      allow(Mcp::Auth::Services::TokenService).to receive(:revoke_refresh_token).and_return(false)

      expect do
        post :token, params: {
          grant_type: 'refresh_token', refresh_token: refresh.token, client_id: client.client_id
        }
      end.not_to change(Mcp::Auth::AccessToken, :count)

      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['error']).to eq('invalid_grant')
    end
  end
end
