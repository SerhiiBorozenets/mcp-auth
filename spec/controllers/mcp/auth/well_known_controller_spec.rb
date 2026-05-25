# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::WellKnownController, type: :controller do
  routes { Mcp::Auth::Engine.routes }

  # Reset TokenService's cached keys before each example so config changes
  # in one example don't leak into the next.
  before do
    Mcp::Auth::Services::TokenService.instance_variable_set(:@cached_private_key, nil)
    Mcp::Auth::Services::TokenService.instance_variable_set(:@cached_public_key, nil)
    Mcp::Auth::Services::TokenService.instance_variable_set(:@jwk, nil)
  end

  describe 'GET #protected_resource' do
    it 'returns protected resource metadata' do
      get :protected_resource

      expect(response).to have_http_status(:ok)
      expect(response.content_type).to eq('application/json; charset=utf-8')

      json = JSON.parse(response.body)
      expect(json['resource']).to be_present
      expect(json['authorization_servers']).to be_an(Array)
      expect(json['scopes_supported']).to include('mcp:read', 'mcp:write')
    end

    it 'sets CORS headers' do
      get :protected_resource

      expect(response.headers['Access-Control-Allow-Origin']).to eq('*')
      expect(response.headers['Access-Control-Allow-Methods']).to eq('GET, OPTIONS')
    end
  end

  describe 'GET #authorization_server' do
    it 'returns authorization server metadata' do
      get :authorization_server

      expect(response).to have_http_status(:ok)

      json = JSON.parse(response.body)
      expect(json['issuer']).to be_present
      expect(json['authorization_endpoint']).to be_present
      expect(json['token_endpoint']).to be_present
      expect(json['scopes_supported']).to include('mcp:read', 'mcp:write')
      expect(json['code_challenge_methods_supported']).to include('S256')
    end
  end

  describe 'GET #openid_configuration' do
    it 'returns OpenID Connect discovery' do
      get :openid_configuration

      expect(response).to have_http_status(:ok)

      json = JSON.parse(response.body)
      expect(json['issuer']).to be_present
      expect(json['jwks_uri']).to be_present
      expect(json['userinfo_endpoint']).to be_present
    end
  end

  describe 'GET #jwks' do
    it 'returns an empty key set when HS256 is configured (HMAC keys are never published)' do
      get :jwks

      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)['keys']).to eq([])
    end

    context 'when RS256 signing is enabled' do
      let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }

      before do
        Mcp::Auth.configure do |c|
          c.token_signing_algorithm = 'RS256'
          c.token_signing_private_key = rsa_key.to_pem
        end
      end

      after do
        Mcp::Auth.configure do |c|
          c.token_signing_algorithm = 'HS256'
          c.token_signing_private_key = nil
          c.token_signing_kid = nil
        end
      end

      it 'publishes the active public key as a JWK' do
        get :jwks

        body = JSON.parse(response.body)
        expect(body['keys'].size).to eq(1)

        jwk = body['keys'].first
        expect(jwk['kty']).to eq('RSA')
        expect(jwk['use']).to eq('sig')
        expect(jwk['alg']).to eq('RS256')
        expect(jwk['kid']).to be_present
        expect(jwk['n']).to be_present
        expect(jwk['e']).to be_present
        expect(jwk).not_to have_key('d') # never publish private exponent
      end
    end
  end

  describe 'GET #openid_configuration (CP-9255 batch 2)' do
    it 'advertises the configured signing algorithm' do
      Mcp::Auth.configure do |c|
        c.token_signing_algorithm = 'RS256'
        c.token_signing_private_key = OpenSSL::PKey::RSA.generate(2048).to_pem
      end

      get :openid_configuration
      body = JSON.parse(response.body)

      expect(body['id_token_signing_alg_values_supported']).to eq(['RS256'])
    ensure
      Mcp::Auth.configure do |c|
        c.token_signing_algorithm = 'HS256'
        c.token_signing_private_key = nil
      end
    end
  end

  describe 'OPTIONS requests' do
    it 'handles preflight requests' do
      process :protected_resource, method: :options

      expect(response).to have_http_status(:no_content)
      expect(response.headers['Access-Control-Allow-Origin']).to eq('*')
    end
  end
end
