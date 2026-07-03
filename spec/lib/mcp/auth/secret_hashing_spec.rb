# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Mcp::Auth::SecretHashing do
  describe '.digest' do
    it 'produces a prefixed SHA-256 digest, not the plaintext' do
      digest = described_class.digest('s3cret')

      expect(digest).to start_with('sha256$')
      expect(digest).not_to include('s3cret')
      expect(digest).to eq("sha256$#{Digest::SHA256.hexdigest('s3cret')}")
    end

    it 're-hashes an already-hashed value (a stored digest is never itself a valid input)' do
      once = described_class.digest('s3cret')
      twice = described_class.digest(once)

      expect(twice).not_to eq(once)
      expect(described_class.digest(once)).to eq(twice) # still deterministic
    end

    it 'returns blank input unchanged' do
      expect(described_class.digest('')).to eq('')
      expect(described_class.digest(nil)).to be_nil
    end
  end

  describe 'a stored digest cannot be replayed as a credential (DB-leak defense)' do
    it 'is not offered as a lookup candidate for itself' do
      stored = described_class.digest('realtoken')
      expect(described_class.lookup_candidates(stored)).not_to include(stored)
    end

    it 'does not authenticate when presented in place of the plaintext' do
      stored = described_class.digest('realsecret')
      expect(described_class.match?(stored, stored)).to be false
    end
  end

  describe '.match?' do
    let(:stored) { described_class.digest('correct-secret') }

    it 'matches a presented plaintext against its stored digest' do
      expect(described_class.match?(stored, 'correct-secret')).to be true
    end

    it 'rejects a wrong plaintext' do
      expect(described_class.match?(stored, 'wrong-secret')).to be false
    end

    it 'rejects blank input' do
      expect(described_class.match?(stored, '')).to be false
      expect(described_class.match?(nil, 'correct-secret')).to be false
    end
  end

  describe 'transitional dual-read' do
    describe '.lookup_candidates' do
      it 'includes both the digest and the raw plaintext while dual-read is on' do
        expect(described_class.lookup_candidates('abc'))
          .to contain_exactly(described_class.digest('abc'), 'abc')
      end

      it 'includes only the digest once dual-read is disabled' do
        allow(Mcp::Auth.configuration).to receive(:secret_dual_read).and_return(false)
        expect(described_class.lookup_candidates('abc')).to eq([described_class.digest('abc')])
      end
    end

    describe '.match?' do
      it 'matches a legacy plaintext stored value while dual-read is on' do
        expect(described_class.match?('legacy-plain', 'legacy-plain')).to be true
      end

      it 'rejects a plaintext stored value once dual-read is disabled' do
        allow(Mcp::Auth.configuration).to receive(:secret_dual_read).and_return(false)
        expect(described_class.match?('legacy-plain', 'legacy-plain')).to be false
      end
    end
  end
end
