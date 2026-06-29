# Contributing to LiteIAM

Thank you for your interest in contributing to LiteIAM! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to uphold it.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Open a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (OS, Python version, etc.)
   - Logs if applicable

### Suggesting Features

Open an issue with the `enhancement` label describing:
- The problem it solves
- Proposed solution
- Any alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Ensure code passes lint: `pip install ruff && ruff check app tests`
6. Commit with conventional format: `feat: add new feature` or `fix: resolve issue`
7. Push and open a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/LiteIAM.git
cd LiteIAM

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest
```

## Project Structure

```
app/
├── api/v1/         # HTTP endpoints
├── authz/          # Authorization (Casbin)
├── core/           # Config, database, events
├── identity/       # Auth flows (password, passkey, social)
├── mfa/            # Multi-factor auth
├── models/         # SQLAlchemy models
├── notifications/  # Email templates
├── sessions/       # Session management
├── shared/         # Shared utilities (http_clients)
├── tenant/         # Multi-tenant routing
├── tokens/         # JWT, key management
├── ui/             # UI routes/templates
└── admin/          # Admin endpoints
```

## Coding Standards

- Python 3.12+, 4-space indentation
- Type hints required for public functions
- Docstrings for modules and complex logic
- Run `ruff format` before committing

## Questions?

Open a discussion or email vishal.vasistha1@gmail.com