# frozen_string_literal: true

module Mcp
  module Auth
    # Raised when the loaded gem needs database columns the app hasn't migrated
    # yet. Carries an actionable message naming the exact command to run.
    class PendingMigrationError < Mcp::Auth::Error; end

    # Detects the common upgrade hazard: a new gem version ships migrations, the
    # app is deployed WITHOUT running them, and the code then blows up at runtime
    # with a cryptic `unknown attribute` / `UndefinedColumn`. This turns that into
    # an explicit, self-explaining condition — a loud boot warning and a clear
    # error at the OAuth endpoints — so the operator knows to run `rails db:migrate`.
    module SchemaGuard
      # Columns each release added beyond the original schema, keyed by model.
      # Extend this whenever a future migration adds a column the code relies on.
      REQUIRED_COLUMNS = {
        'Mcp::Auth::OauthClient' => %w[token_endpoint_auth_method],
        'Mcp::Auth::RefreshToken' => %w[family_id revoked_at]
      }.freeze

      module_function

      # "table.column" entries the code needs but the database is missing. Empty
      # when the schema is current. NEVER raises and returns [] when the database
      # isn't available or a table doesn't exist yet (fresh install, `db:create`,
      # asset precompile, CI without a database) so it can't break boot or tasks.
      def missing_columns
        REQUIRED_COLUMNS.flat_map do |model_name, columns|
          model = model_name.constantize
          next [] unless model.table_exists?

          (columns - model.column_names).map { |column| "#{model.table_name}.#{column}" }
        end
      rescue StandardError => e
        # ActiveRecord::NoDatabaseError, ConnectionNotEstablished, StatementInvalid,
        # etc. — we simply can't check here, so treat as "nothing to report".
        Rails.logger.debug { "[mcp-auth] schema check skipped: #{e.class}" } if defined?(Rails)
        []
      end

      def up_to_date?
        missing_columns.empty?
      end

      # Raise unless the schema is current (used where a hard failure is wanted).
      def check!
        missing = missing_columns
        return true if missing.empty?

        raise PendingMigrationError, guidance(missing)
      end

      def guidance(missing = missing_columns)
        "mcp-auth #{Mcp::Auth::VERSION} needs a database migration — missing #{missing.join(', ')}. " \
          'Run `rails g mcp:auth:upgrade && rails db:migrate`, then restart.'
      end
    end
  end
end
