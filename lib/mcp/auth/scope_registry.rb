# frozen_string_literal: true

module Mcp
  module Auth
    class ScopeRegistry
      class << self
        # Default MCP scopes - minimal set
        def default_scopes
          {
            'mcp:read' => {
              name: 'Read Access',
              description: 'Read your data and resources',
              required: true
            },
            'mcp:write' => {
              name: 'Write Access',
              description: 'Create and modify data on your behalf',
              required: false
            }
          }
        end

        # Custom scopes registered by the application
        def custom_scopes
          @custom_scopes ||= {}
        end

        # All available scopes (default + custom)
        def available_scopes
          default_scopes.merge(custom_scopes)
        end

        # Register a custom scope
        def register_scope(scope_key, name:, description:, required: false)
          custom_scopes[scope_key.to_s] = {
            name: name,
            description: description,
            required: required
          }
        end

        # Clear custom scopes (useful for testing)
        def clear_custom_scopes!
          @custom_scopes = {}
        end

        # Check if a scope exists
        def scope_exists?(scope)
          available_scopes.key?(scope.to_s)
        end

        # Get scope metadata
        def scope_metadata(scope)
          available_scopes[scope.to_s] || {
            name: scope,
            description: scope,
            required: false
          }
        end

        # Validate and filter requested scopes
        def validate_scopes(requested_scopes)
          return %w[mcp:read mcp:write] if requested_scopes.blank?

          scopes = requested_scopes.is_a?(String) ? requested_scopes.split : requested_scopes

          # Filter to only valid registered scopes
          valid_scopes = scopes.select { |scope| scope_exists?(scope) }

          # Always include required scopes
          required_scopes = available_scopes.select { |_, meta| meta[:required] }.keys

          (valid_scopes + required_scopes).uniq
        end

        # Format scopes for consent screen display
        def format_for_display(requested_scopes)
          scopes = requested_scopes.is_a?(String) ? requested_scopes.split : requested_scopes

          scopes.map do |scope|
            metadata = scope_metadata(scope)
            {
              key: scope,
              name: metadata[:name],
              description: metadata[:description],
              required: metadata[:required]
            }
          end
        end
      end
    end
  end
end
