# frozen_string_literal: true

module Mcp
  module Auth
    # ScopeRegistry manages OAuth scopes for MCP Auth
    #
    # By default, provides basic MCP scopes (mcp:read, mcp:write) automatically.
    # Applications can register custom scopes which will replace the defaults.
    #
    # Example:
    #   Mcp::Auth::ScopeRegistry.register_scope('mcp:tools',
    #     name: 'Tool Execution',
    #     description: 'Execute tools and actions',
    #     required: false
    #   )
    class ScopeRegistry
      class << self
        # Custom scopes registered by the application
        def custom_scopes
          @custom_scopes ||= {}
        end

        # All available scopes
        # If no scopes are registered, returns basic MCP scopes for backwards compatibility
        def available_scopes
          return custom_scopes unless custom_scopes.empty?

          # Fallback: If no scopes registered, use basic MCP scopes
          # This ensures backwards compatibility
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

        # Register a custom scope
        def register_scope(scope_key, name:, description:, required: false)
          custom_scopes[scope_key.to_s] = {
            name: name,
            description: description,
            required: required
          }
        end

        # Clear all registered scopes (useful for testing)
        def clear_scopes!
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
          # If no scopes requested, return all required scopes
          if requested_scopes.blank?
            return available_scopes.select { |_, meta| meta[:required] }.keys
          end

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

        # Get default scopes string for a client
        def default_scope_string
          # Return all registered scopes, or empty string if none
          available_scopes.keys.join(' ')
        end
      end
    end
  end
end
