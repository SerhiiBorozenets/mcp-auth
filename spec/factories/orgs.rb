# frozen_string_literal: true

require_relative '../dummy/app/models/org'

FactoryBot.define do
  factory :org, class: '::Org' do
    name { Faker::Company.name }
  end
end