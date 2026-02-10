# Contributing to TaipanStack

First off, thank you for considering contributing to TaipanStack! It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is expected to uphold professional and respectful behavior. Please be kind and courteous.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples
- Describe the behavior you observed and what you expected
- Include your environment details (OS, Python version, Poetry version)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a detailed description of the suggested enhancement
- Explain why this enhancement would be useful
- List any alternative solutions you've considered

### Pull Requests

1. Fork the repository and create your branch from `main`
2. Make your changes following our coding standards
3. Add tests for any new functionality
4. Ensure the test suite passes
5. Make sure your code lints
6. Update documentation as needed
7. Write a clear commit message

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Poetry (install via `pipx install poetry`)
- Git

### Setting Up Your Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/TaipanStack.git
cd TaipanStack

# Install dependencies
poetry install --with dev

# Activate virtual environment
poetry shell

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Code Quality Checks

```bash
# Run linter
ruff check src/ tests/ taipanstack_bootstrapper.py

# Run formatter
ruff format src/ tests/ taipanstack_bootstrapper.py

# Run type checker
mypy src/ --strict

# Run security scanner
bandit -r src/

# Check dependencies for vulnerabilities
safety check
```

### Using Makefile

```bash
# Run tests
make test

# Run linting
make lint

# Format code
make format

# Clean cache files
make clean

# Run all checks
make all
```

## Coding Standards

### Python Style

- Follow PEP 8 style guide
- Use type hints for all function signatures
- Write docstrings for all public functions and classes
- Maximum line length: 88 characters (Black/Ruff default)
- Use f-strings for string formatting
- Prefer pathlib over os.path

### Documentation

- Write clear, concise docstrings
- Update README.md if adding user-facing features
- Add comments for non-obvious code logic
- Keep CHANGELOG.md updated

### Testing

- Write tests for all new functionality
- Aim for high test coverage (80%+)
- Use descriptive test names: `test_<what>_<condition>_<expected>`
- Use fixtures for setup/teardown
- Mock external dependencies

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(security): add SQL injection guard

Add new guard function to prevent SQL injection attacks
in database queries.

Closes #42
```

## Project Structure

```
TaipanStack/
├── taipanstack_bootstrapper.py  # Bootstrapper script
├── src/
│   ├── app/                     # Application entry point
│   └── taipanstack/             # Main package
│       ├── core/                # Result types, patterns
│       ├── config/              # Configuration
│       ├── security/            # Security utilities
│       └── utils/               # General utilities
├── tests/
│   └── *.py                     # Test files
├── .github/
│   └── workflows/
│       └── ci.yml
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE
└── pyproject.toml
```

## Release Process

1. Update version in `pyproject.toml` and `src/taipanstack/__init__.py`
2. Update `CHANGELOG.md` with release notes
3. Create a git tag: `git tag -a v2.0.0 -m "Release v2.0.0"`
4. Push tag: `git push origin v2.0.0`
5. GitHub Actions will automatically create a release
6. Publish to PyPI: `poetry publish --build`

## Questions?

Feel free to open an issue with the `question` label if you have any questions about contributing!

Thank you for your contributions! 🎉
