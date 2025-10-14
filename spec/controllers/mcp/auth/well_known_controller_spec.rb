# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::WellKnownController, type: :controller do
  routes { Mcp::Auth::Engine.routes }

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
    it 'returns empty JWKS' do
      get :jwks

      expect(response).to have_http_status(:ok)

      json = JSON.parse(response.body)
      expect(json['keys']).to eq([])
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
