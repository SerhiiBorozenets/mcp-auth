# frozen_string_literal: true

ActiveRecord::Schema[7.0].define(version: 0) do
  create_table "users", force: :cascade do |t|
    t.string "email", null: false
    t.string "password_digest"
    t.timestamps
  end

  create_table "orgs", force: :cascade do |t|
    t.string "name", null: false
    t.timestamps
  end

  create_table "mcp_auth_oauth_clients", primary_key: "client_id", id: :string, force: :cascade do |t|
    t.string "client_secret", null: false
    t.text "redirect_uris"
    t.text "grant_types"
    t.text "response_types"
    t.string "scope"
    t.string "client_name"
    t.string "client_uri"
    t.timestamps
  end

  create_table "mcp_auth_authorization_codes", force: :cascade do |t|
    t.string "code", null: false
    t.string "client_id", null: false
    t.string "redirect_uri", null: false
    t.string "code_challenge"
    t.string "code_challenge_method"
    t.string "resource"
    t.string "scope"
    t.integer "user_id", null: false
    t.integer "org_id"
    t.datetime "expires_at", null: false
    t.timestamps

    t.index ["code"], name: "index_mcp_auth_authorization_codes_on_code", unique: true
    t.index ["user_id"], name: "index_mcp_auth_authorization_codes_on_user_id"
    t.index ["org_id"], name: "index_mcp_auth_authorization_codes_on_org_id"
  end

  create_table "mcp_auth_access_tokens", force: :cascade do |t|
    t.string "token", null: false
    t.string "client_id", null: false
    t.string "resource"
    t.string "scope"
    t.integer "user_id", null: false
    t.integer "org_id"
    t.datetime "expires_at", null: false
    t.timestamps

    t.index ["token"], name: "index_mcp_auth_access_tokens_on_token", unique: true
    t.index ["user_id"], name: "index_mcp_auth_access_tokens_on_user_id"
    t.index ["org_id"], name: "index_mcp_auth_access_tokens_on_org_id"
  end

  create_table "mcp_auth_refresh_tokens", force: :cascade do |t|
    t.string "token", null: false
    t.string "client_id", null: false
    t.string "scope"
    t.integer "user_id", null: false
    t.integer "org_id"
    t.datetime "expires_at", null: false
    t.timestamps

    t.index ["token"], name: "index_mcp_auth_refresh_tokens_on_token", unique: true
    t.index ["user_id"], name: "index_mcp_auth_refresh_tokens_on_user_id"
    t.index ["org_id"], name: "index_mcp_auth_refresh_tokens_on_org_id"
  end
end
