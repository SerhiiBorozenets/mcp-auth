# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'generated initializer template' do
  let(:template) do
    File.read(File.expand_path('../../../../lib/generators/mcp/auth/templates/initializer.rb', __dir__))
  end

  it 'keeps every (commented) config.* setting inside the Mcp::Auth.configure block' do
    lines = template.lines
    block_end = lines.index("end\n")
    setting_lines = lines.each_index.select { |i| lines[i] =~ /\A\s*#?\s*config\.\w+/ }

    # Uncommenting any setting (e.g. `config.secret_dual_read = false`) must not
    # land outside the block, where `config` is undefined (NameError at boot).
    expect(setting_lines).to all(be < block_end)
  end

  it 'does not fall back to secret_key_base for the signing secret' do
    expect(template).not_to match(/oauth_secret\s*=.*secret_key_base/)
  end
end
