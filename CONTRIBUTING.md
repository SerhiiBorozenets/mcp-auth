# Contributing to MCP Auth

Thank you for your interest in contributing to MCP Auth! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful and inclusive. We're all here to build great software together.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- Clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Ruby and Rails versions
- Any relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- Clear, descriptive title
- Detailed description of the proposed functionality
- Explanation of why this enhancement would be useful
- Possible implementation approach (optional)

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure all tests pass (`bundle exec rspec`)
6. Run RuboCop (`bundle exec rubocop`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

#### Pull Request Guidelines

- Follow the existing code style
- Write clear, descriptive commit messages
- Include tests for new functionality
- Update documentation as needed
- Keep PRs focused on a single feature or bug fix
- Ensure CI passes before requesting review

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/SerhiiBorozenets/mcp-auth.git
cd mcp-auth
```

2. Install dependencies:
```bash
bundle install
```

3. Run tests:
```bash
bundle exec rspec
```

4. Run linter:
```bash
bundle exec rubocop
```

## Testing

- Write tests for all new features and bug fixes
- Maintain or improve code coverage
- Use RSpec for testing
- Follow existing test patterns

## Code Style

- Follow Ruby Style Guide
- Use RuboCop for linting
- Keep methods small and focused
- Write descriptive variable and method names
- Add comments for complex logic

## Documentation

- Update README.md for user-facing changes
- Add YARD documentation for public APIs
- Update CHANGELOG.md following Keep a Changelog format
- Include examples for new features

## Security

If you discover a security vulnerability, please email [security@example.com] instead of creating a public issue. We'll work with you to address it promptly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue for any questions about contributing!