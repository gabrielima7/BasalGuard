<div align="center">

# 🐍 TaipanStack

### **The Modern Python Foundation**

*Launch secure, high-performance Python applications in seconds.*

[![CI](https://github.com/gabrielima7/TaipanStack/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gabrielima7/TaipanStack/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Coverage](https://img.shields.io/badge/Coverage-98%25-success?style=flat&logo=codecov)](https://github.com/gabrielima7/TaipanStack)
[![Code Style](https://img.shields.io/badge/Code%20Style-Ruff-D7FF64?style=flat&logo=ruff&logoColor=black)](https://github.com/astral-sh/ruff)
[![Type Checked](https://img.shields.io/badge/Type%20Checked-Mypy-blue?style=flat)](http://mypy-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Bandit%20%7C%20Semgrep-red?style=flat)](SECURITY.md)
[![PyPI](https://img.shields.io/pypi/v/taipanstack?style=flat&logo=pypi&logoColor=white)](https://pypi.org/project/taipanstack/)

---

[**Features**](#-features) • [**Quick Start**](#-quick-start) • [**Architecture**](#-architecture) • [**DevSecOps**](#-devsecops) • [**API**](#-api-highlights) • [**Contributing**](#-contributing)

</div>

---

## ✨ Why TaipanStack?

> **"Write less, build better."**

TaipanStack is a battle-tested foundation for production-grade Python projects that combines **security**, **performance**, and **developer experience** into a single, cohesive toolkit.

<table>
<tr>
<td width="50%">

### 🛡️ Security First
- Path traversal protection
- Command injection guards
- Input sanitizers & validators
- Secret detection integration

</td>
<td width="50%">

### ⚡ High Performance
- `uvloop` async event loop
- `orjson` fast JSON serialization
- `Pydantic v2` validation
- Optimized for production

</td>
</tr>
<tr>
<td width="50%">

### 🎯 Rust-Style Error Handling
- `Ok`/`Err` Result types
- Explicit error propagation
- Pattern matching support
- No silent failures

</td>
<td width="50%">

### 🔧 Developer Experience
- Pre-configured quality tools
- Comprehensive test suite
- Architecture enforcement
- Zero-config setup

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** (supports 3.11, 3.12, 3.13, 3.14)
- **Poetry** ([install guide](https://python-poetry.org/docs/#installation))

### Installation

#### From PyPI

```bash
pip install taipanstack
```

#### From Source

```bash
# Clone the repository
git clone https://github.com/gabrielima7/TaipanStack.git
cd TaipanStack

# Install dependencies
poetry install --with dev

# Run quality checks
make all
```

### Verify Installation

```bash
# Run tests with coverage (97%+ coverage)
make test

# Check architecture contracts
make lint-imports

# Run security scans
make security
```

---

## 📐 Architecture

TaipanStack follows a clean, layered architecture with strict dependency rules enforced by **Import Linter**.

```
                    ┌─────────────────────────────────────┐
                    │             Application             │
                    │          (src/app/main.py)          │
                    └─────────────────┬───────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          ▼                           ▼                           ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│    Security     │       │     Config      │       │     Utils       │
│ guards, saniti- │       │    models,      │       │  logging, retry │
│ zers, validators│       │   generators    │       │ metrics, fs     │
└────────┬────────┘       └────────┬────────┘       └────────┬────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │              Core                   │
                    │    Result types, base patterns      │
                    └─────────────────────────────────────┘
```

### Project Structure

```text
TaipanStack/
├── src/
│   ├── app/              # Application entry point
│   └── taipanstack/
│       ├── core/         # 🎯 Result types, functional patterns
│       ├── config/       # ⚙️ Configuration models & generators
│       ├── security/     # 🛡️ Guards, sanitizers, validators
│       └── utils/        # 🔧 Logging, metrics, retry, filesystem
├── tests/                # ✅ Comprehensive test suite (97%+ coverage)
├── pyapp/                # 📦 Standalone executable builder
├── .github/              # 🔄 CI/CD workflows
└── pyproject.toml        # 📋 Modern dependency management
```

---

## 🔐 DevSecOps

TaipanStack integrates security and quality at every level:

| Category | Tools | Purpose |
|----------|-------|---------|
| **SAST** | Bandit, Semgrep | Static Application Security Testing |
| **SCA** | Safety | Dependency vulnerability scanning |
| **Types** | Mypy (strict) | Compile-time type checking |
| **Lint** | Ruff | Lightning-fast linting & formatting |
| **Arch** | Import Linter | Dependency rule enforcement |
| **Test** | Pytest, Hypothesis | Property-based testing |

### CI Pipeline

```yaml
# Runs on every push/PR
✓ Test Matrix     → Python 3.11-3.14 × (Ubuntu, macOS, Windows)
✓ Linux Distros   → Ubuntu, Debian, Fedora, openSUSE, Arch, Alpine
✓ Code Quality    → Ruff check & format
✓ Type Check      → Mypy strict mode
✓ Security        → Bandit + Semgrep
✓ Architecture    → Import Linter contracts
```

---

## 📚 API Highlights

### Result Types (Rust-Style Error Handling)

```python
from taipanstack.core.result import Result, Ok, Err, safe

@safe
def divide(a: int, b: int) -> float:
    return a / b

# Explicit error handling with pattern matching
match divide(10, 0):
    case Ok(value):
        print(f"Result: {value}")
    case Err(error):
        print(f"Error: {error}")
```

### Security Guards

```python
from taipanstack.security.guards import guard_path_traversal, guard_command_injection

# Prevent path traversal attacks
safe_path = guard_path_traversal(user_input, base_dir="/app/data")

# Prevent command injection
safe_cmd = guard_command_injection(
    ["git", "clone", repo_url],
    allowed_commands=["git"]
)
```

### Retry with Exponential Backoff

```python
from taipanstack.utils.retry import retry

@retry(max_attempts=3, on=(ConnectionError, TimeoutError))
async def fetch_data(url: str) -> dict:
    return await http_client.get(url)
```

### Circuit Breaker

```python
from taipanstack.utils.circuit_breaker import circuit_breaker

@circuit_breaker(failure_threshold=5, timeout=30)
def call_external_service() -> Response:
    return service.call()
```

---

## 🛠️ Tech Stack

<table>
<tr>
<th>Runtime</th>
<th>Quality</th>
<th>DevOps</th>
</tr>
<tr>
<td>

- Pydantic v2
- Orjson
- Uvloop
- Structlog
- Result

</td>
<td>

- Ruff
- Mypy
- Bandit
- Pytest
- Hypothesis

</td>
<td>

- GitHub Actions
- Dependabot
- Pre-commit
- Poetry
- Import Linter

</td>
</tr>
</table>

---

## 🤝 Contributing

Contributions are welcome! Please check our [Contributing Guide](CONTRIBUTING.md) for details on:

- 🐛 Bug reports
- ✨ Feature requests
- 📝 Documentation improvements
- 🔧 Pull requests

---

## 📝 License

This project is open-sourced under the [MIT License](LICENSE).

---

<div align="center">

**Made with ❤️ for the Python community**

[⬆ Back to Top](#-taipanstack)

</div>
