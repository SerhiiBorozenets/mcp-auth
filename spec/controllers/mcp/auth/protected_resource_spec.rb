# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::ProtectedResource, type: :controller do
  let(:user) { create(:user) }
  let(:oauth_client) { create(:oauth_client) }
  let(:token) do
    Mcp::Auth::Services::TokenService.generate_access_token(
      {
        client_id: oauth_client.client_id,
        user_id: user.id,
        scope: 'mcp:read',
        resource: 'http://test.host/mcp'
      },
      base_url: 'http://test.host'
    )
  end

  describe 'token authentication' do
    controller(ActionController::Base) do
      include Mcp::Auth::ProtectedResource

      before_action :authenticate_mcp_token!

      def index
        render json: { user_id: mcp_user_id, scope: mcp_scope }
      end
    end

    before { routes.draw { get 'index' => 'anonymous#index' } }

    it 'rejects a request with no token and advertises the metadata (RFC 9728)' do
      get :index

      expect(response).to have_http_status(:unauthorized)
      expect(response.headers['WWW-Authenticate']).to include('Bearer')
      expect(response.headers['WWW-Authenticate']).to include('resource_metadata=')
      expect(JSON.parse(response.body)['error']).to eq('invalid_token')
    end

    it 'rejects a revoked token' do
      revoked = token
      Mcp::Auth::AccessToken.find_by(token: revoked).destroy
      request.headers['Authorization'] = "Bearer #{revoked}"

      get :index

      expect(response).to have_http_status(:unauthorized)
    end

    it 'allows a valid token and exposes the claims to the controller' do
      request.headers['Authorization'] = "Bearer #{token}"

      get :index

      expect(response).to have_http_status(:ok)
      body = JSON.parse(response.body)
      expect(body['user_id']).to eq(user.id.to_s)
      expect(body['scope']).to eq('mcp:read')
    end
  end

  describe 'scope enforcement' do
    controller(ActionController::Base) do
      include Mcp::Auth::ProtectedResource

      before_action :authenticate_mcp_token!
      before_action -> { require_mcp_scope!('mcp:admin') }

      def index
        render json: { ok: true }
      end
    end

    before { routes.draw { get 'index' => 'anonymous#index' } }

    it 'returns 403 insufficient_scope when the token lacks the scope' do
      request.headers['Authorization'] = "Bearer #{token}"

      get :index

      expect(response).to have_http_status(:forbidden)
      expect(JSON.parse(response.body)['error']).to eq('insufficient_scope')
    end
  end
end
