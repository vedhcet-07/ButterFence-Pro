# Contributing to ButterFence Pro

Thank you for your interest in contributing to ButterFence Pro! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/ButterFence-Pro.git
   cd ButterFence-Pro
   ```

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip and virtualenv

### Setup Instructions

1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install the package in editable mode with all development dependencies:
   ```bash
   pip install -e '.[dev,gemini,api,edge,pdf]'
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Making Changes

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code style guidelines below

3. Add tests for your changes in the `tests/` directory

4. Ensure all tests pass:
   ```bash
   pytest tests/
   ```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=butterfence --cov-report=term-missing

# Run specific test file
pytest tests/test_matcher.py

# Run tests matching a pattern
pytest tests/ -k "test_security"
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files as `test_*.py`
- Use descriptive test function names: `test_should_block_rm_rf_command()`
- Follow the Arrange-Act-Assert pattern
- Add docstrings to test functions explaining what is being tested

Example:
```python
def test_should_block_destructive_shell_command():
    """Test that matcher blocks rm -rf / command."""
    # Arrange
    payload = create_test_payload("rm -rf /")
    
    # Act
    result = match_patterns(payload, config)
    
    # Assert
    assert result.decision == Decision.BLOCK
    assert result.category == "destructive_shell"
```

## Code Style

### Python Style Guide

This project follows PEP 8 and uses several tools to enforce code quality:

- **Black**: Code formatting (line length: 100)
- **isort**: Import sorting
- **Ruff**: Fast Python linter
- **Pylint**: Static code analysis
- **MyPy**: Static type checking

### Running Linters

```bash
# Format code with black
black src/ tests/

# Sort imports
isort src/ tests/

# Run ruff linter
ruff check src/ tests/

# Run pylint
pylint src/butterfence/

# Run type checker
mypy src/butterfence/
```

### Pre-commit Hooks

Pre-commit hooks will automatically run these tools on changed files:

```bash
# Install hooks (one time)
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

### Code Conventions

- Use type hints for function parameters and return values
- Write docstrings for all public modules, classes, and functions
- Keep functions focused and under 50 lines when possible
- Use descriptive variable names (avoid single letters except in comprehensions)
- Add comments for complex logic

### Docstring Style

Use Google-style docstrings:

```python
def match_pattern(text: str, pattern: str) -> bool:
    """Check if text matches the given pattern.
    
    Args:
        text: The text to search within.
        pattern: The regex pattern to match.
    
    Returns:
        True if pattern matches, False otherwise.
    
    Raises:
        ValueError: If pattern is invalid regex.
    """
    ...
```

## Submitting Changes

### Before Submitting

1. Ensure all tests pass:
   ```bash
   pytest tests/
   ```

2. Run linters and fix any issues:
   ```bash
   black src/ tests/
   isort src/ tests/
   ruff check --fix src/ tests/
   ```

3. Update documentation if needed

4. Add entry to CHANGELOG.md (if applicable)

### Pull Request Process

1. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub with:
   - Clear title describing the change
   - Description of what changed and why
   - Reference to any related issues (e.g., "Fixes #123")
   - Screenshots for UI changes

3. Wait for review and address any feedback

4. Once approved, a maintainer will merge your PR

### Commit Messages

Write clear commit messages following this format:

```
[type]: Brief description (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain what changed and why, not how.

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat: Add multi-model red team support

Implement concurrent Claude + Gemini red team attacks to find
cross-model blind spots in security defenses.

Fixes #42
```

## Security Issues

**Do not open public issues for security vulnerabilities.**

Please report security issues privately to the maintainers. See SECURITY.md for details.

## Questions?

Feel free to open an issue for questions about contributing or reach out to the maintainers.

Thank you for contributing to ButterFence Pro! 🎉
