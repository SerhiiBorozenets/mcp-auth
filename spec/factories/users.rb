# frozen_string_literal: true

require_relative '../dummy/app/models/user'

FactoryBot.define do
  factory :user, class: '::User' do
    email { Faker::Internet.email }
  end
end