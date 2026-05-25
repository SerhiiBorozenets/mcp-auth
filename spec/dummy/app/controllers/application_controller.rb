# frozen_string_literal: true

# Minimal host-app base controller for the gem's dummy specs. Real apps will
# have their own ApplicationController; Mcp::Auth::OauthController inherits
# from whichever one is in scope.
class ApplicationController < ActionController::Base
  def current_user
    nil
  end

  def current_org
    nil
  end

  def user_signed_in?
    false
  end
end
