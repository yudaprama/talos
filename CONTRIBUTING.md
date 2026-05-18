# Contributing to Ory Talos

Thank you for your interest in contributing to Ory Talos!

## Development Setup

### Prerequisites

- Go 1.23 or later
- Make
- Git
- Node.js 18+ (for documentation testing)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/ory-corp/talos.git
cd talos

# Install dependencies
make deps

# Build the binary
make build

# Run tests
make test

# Run full verification
make verify
```

## Development Workflow

1. **Fork the repository**
2. **Create a feature branch** - `git checkout -b feat/my-feature`
3. **Make your changes**
4. **Add tests** - All new code must have tests
5. **Run verification** - `make verify` must pass
6. **Commit with clear messages** - Follow conventional commits
7. **Push and create PR** - Target the `first-implementation` branch

## Code Guidelines

Please follow the guidelines in [CLAUDE.md](AGENTS.md):

- ✅ No global state; inject all dependencies
- ✅ Always pass `context.Context` from caller
- ✅ Use structured JSON logging (slog)
- ✅ Never use `COUNT(*)`, `SELECT *`, or `OFFSET`
- ✅ Commercial code under `/commercial/` with build tags

## Testing Requirements

- **Coverage** - Target ≥85% (goal 90%)
- **Table-driven tests** - Use `t.Run()` for subtests
- **Parallel execution** - Use `t.Parallel()` where safe
- **Happy + unhappy paths** - Test error cases
- **Documentation tests** - Ensure examples work

## Documentation

- **API docs** - Auto-generated from protobuf
- **Tutorials** - Must have executable examples
- **Guides** - Clear, actionable content

Run documentation tests:

```bash
make docs-test
```

## Pull Request Process

1. Update documentation if needed
2. Add/update tests for your changes
3. Ensure `make verify` passes
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

## Code of Conduct

- Be respectful and constructive
- Focus on the code, not the person
- Help others learn and grow
- Assume good intentions

## Questions?

- Open an issue for bugs or feature requests
- Join discussions for questions
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
