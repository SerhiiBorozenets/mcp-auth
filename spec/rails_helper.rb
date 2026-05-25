# frozen_string_literal: true

require 'spec_helper'

# Load the dummy app's ApplicationController so OauthController can inherit from
# it during controller specs (Mcp::Auth::OauthController < ApplicationController).
require File.expand_path('dummy/app/controllers/application_controller', __dir__)

RSpec.configure do |config|
  config.fixture_paths = ["#{::Rails.root}/spec/fixtures"]
  config.use_transactional_fixtures = true
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!
end