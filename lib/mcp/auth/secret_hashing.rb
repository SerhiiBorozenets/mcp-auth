# frozen_string_literal: true

require 'digest'

module Mcp
  module Auth
    # One-way hashing for the secrets we persist: client secrets, access tokens,
    # refresh tokens, and authorization codes.
    #
    # We only ever *verify* these values against a copy the caller presents later
    # — we never need to read the original back. That makes a one-way hash
    # strictly safer than reversible encryption: a database leak yields useless
    # digests, and there is no decryption key that (if it also leaked) could turn
    # them back into working credentials.
    #
    # The values are high-entropy (>= 256-bit SecureRandom, or signed JWTs), so a
    # single unsalted SHA-256 is sufficient — there is no dictionary/brute-force
    # risk the way there is for low-entropy passwords (which would need bcrypt/
    # argon2). SHA-256 is also deterministic, which lets us look a token up
    # directly by its digest through the existing unique index.
    #
    # Digests are stored with a `sha256$` prefix so they are self-identifying:
    # this makes the backfill migration idempotent (a value already carrying the
    # prefix is left alone) and leaves room to introduce a different scheme later
    # without ambiguity.
    module SecretHashing
      PREFIX = 'sha256$'

      module_function

      # Digest a plaintext value for storage/lookup. Already-hashed values are
      # returned unchanged so the function is safe to apply idempotently (e.g. in
      # the backfill migration). Blank input is returned as-is.
      def digest(value)
        return value if value.blank? || hashed?(value)

        "#{PREFIX}#{Digest::SHA256.hexdigest(value.to_s)}"
      end

      def hashed?(value)
        value.to_s.start_with?(PREFIX)
      end

      # Whether transitional dual-read is active (see Configuration#secret_dual_read).
      # Defaults to true when configuration is absent so an un-configured app
      # still upgrades safely.
      def dual_read?
        config = Mcp::Auth.configuration
        config.nil? || config.secret_dual_read != false
      end

      # The stored-column values a presented secret could legitimately match:
      # always its digest, plus — while dual-read is enabled — the raw plaintext,
      # so a legacy row not yet backfilled by the migration still resolves. Use
      # with `where(column: candidates)`.
      def lookup_candidates(value)
        return [] if value.blank?

        candidates = [digest(value)]
        candidates << value.to_s if dual_read? && !hashed?(value)
        candidates.uniq
      end

      # Constant-time verification of a presented plaintext against a stored
      # value. Matches the digest form, and — under dual-read — a legacy plaintext
      # row as well.
      def match?(stored, presented)
        return false if stored.blank? || presented.blank?

        return true if ActiveSupport::SecurityUtils.secure_compare(stored.to_s, digest(presented.to_s))

        dual_read? && !hashed?(stored) &&
          ActiveSupport::SecurityUtils.secure_compare(stored.to_s, presented.to_s)
      end
    end
  end
end
