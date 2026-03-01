# Contributing to AiKey CLI

Thank you for your interest in contributing to AiKey CLI! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- Basic understanding of cryptography concepts (helpful but not required)

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aikeylabs/aikey-cli.git
   cd aikey-cli
   ```

2. **Build the project:**
   ```bash
   cargo build
   ```

3. **Run tests:**
   ```bash
   cargo test
   ```

4. **Run the CLI:**
   ```bash
   cargo run -- --help
   ```

## Development Workflow

### Before You Start

1. Check existing issues and pull requests to avoid duplicate work
2. For major changes, open an issue first to discuss your proposal
3. Fork the repository and create a feature branch

### Making Changes

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Write clear, concise code
   - Follow Rust conventions and idioms
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes:**
   ```bash
   cargo test
   cargo clippy
   cargo fmt --check
   ```

4. **Commit your changes:**
   ```bash
   git commit -m "feat: add your feature description"
   ```

   Use conventional commit messages:
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `test:` - Test changes
   - `refactor:` - Code refactoring
   - `chore:` - Maintenance tasks

### Submitting a Pull Request

1. Push your branch to your fork
2. Open a pull request against the `main` branch
3. Provide a clear description of:
   - What changes you made
   - Why you made them
   - How to test them
4. Link any related issues
5. Wait for review and address feedback

## Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Address clippy warnings (`cargo clippy`)
- Write clear comments for complex logic
- Keep functions focused and concise
- Use meaningful variable names

## Testing

- All new features must include tests
- Maintain or improve code coverage
- Test both success and error cases
- Run the full test suite before submitting:
  ```bash
  cargo test --all-targets
  ```

## Documentation

- Update README.md if adding user-facing features
- Add doc comments for public APIs
- Update relevant documentation in `docs/`
- Include examples for new functionality
- Ensure documentation aligns with Stage 0 contract (no plaintext export, runtime-only injection)

## Security

- Never commit secrets or credentials
- Follow secure coding practices
- Report security vulnerabilities privately to aikeyfounder@gmail.com
- See SECURITY.md for more details
- Ensure new features align with Stage 0 security contract (no plaintext export, runtime-only injection)

## Code Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, a maintainer will merge your PR
4. Your contribution will be included in the next release

## Questions?

- Open an issue for questions about the codebase
- Check existing documentation in the `docs/` directory
- Review README.md for Stage 0 architecture and security principles

## License

By contributing to AiKey CLI, you agree that your contributions will be licensed under the Apache-2.0 License.

Thank you for contributing! 🎉
