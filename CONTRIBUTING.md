# Contributing to IAM Explorer

First off, thanks for taking the time to contribute! 🎉 This document outlines our guidelines and best practices for contributing to **IAM Explorer** - a powerful tool for analyzing AWS IAM relationships and permissions.

## Table of Contents
- [Contributing to IAM Explorer](#contributing-to-iam-explorer)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Development Environment](#development-environment)
  - [Project Structure](#project-structure)
  - [Testing](#testing)
    - [Running Tests](#running-tests)
    - [Writing Tests](#writing-tests)
    - [Mocking AWS Services](#mocking-aws-services)
  - [Code Quality](#code-quality)
    - [Coding Style](#coding-style)
    - [Type Hints](#type-hints)
    - [Documentation](#documentation)
  - [Commit Messages](#commit-messages)
  - [Pull Requests](#pull-requests)
  - [Feature Development Guidelines](#feature-development-guidelines)
  - [Security Considerations](#security-considerations)
  - [Performance Guidelines](#performance-guidelines)
  - [Release Process](#release-process)
  - [Getting Help](#getting-help)

---

## Getting Started

### Prerequisites

- **Python 3.10+** (tested with Python 3.10-3.13)
- **AWS CLI** configured with appropriate credentials (for testing with real AWS data)
- **Git** for version control
- **Basic understanding of AWS IAM** concepts

### Quick Setup

1. **Fork and Clone**
   ```bash
   # Fork the repository on GitHub first, then:
   git clone https://github.com/YOUR_USERNAME/iam-explorer.git
   cd iam-explorer
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # .\venv\Scripts\activate  # On Windows

   # Install in development mode
   pip install --upgrade pip
   pip install -e .

   # Install development dependencies
   pip install pytest pytest-cov black flake8 mypy
   ```

3. **Verify Installation**
   ```bash
   # Test the CLI
   iam-explorer --help

   # Run tests
   pytest tests/

   # Run example
   python examples/basic_usage.py
   ```

4. **Set Up Git Remotes**
   ```bash
   git remote add upstream https://github.com/Saff-Buraq-Dev/iam-explorer.git
   git fetch upstream
   ```

---

## Development Environment

### Recommended Tools

- **IDE**: VS Code, PyCharm, or any editor with Python support
- **Python Version Manager**: pyenv or conda for managing Python versions
- **AWS Tools**: AWS CLI v2, AWS SDK for Python (boto3)
- **Graph Visualization**: Graphviz (for converting DOT files to images)

### Environment Variables

For development and testing, you may want to set:

```bash
export AWS_PROFILE=your-dev-profile
export AWS_REGION=us-east-1
export IAM_EXPLORER_LOG_LEVEL=DEBUG
```

### Installing Graphviz (Optional)

For visualization features:

```bash
# macOS
brew install graphviz

# Ubuntu/Debian
sudo apt-get install graphviz

# Windows
# Download from https://graphviz.org/download/
```

---

## Project Structure

Here's the current project layout:

```
iam-explorer/
├── .github/                    # GitHub workflows and templates
│   └── workflows/
├── src/
│   └── iam_explorer/          # Main package
│       ├── __init__.py        # Package initialization and exports
│       ├── cli.py             # Command-line interface (Click)
│       ├── fetcher.py         # AWS IAM data fetching (boto3)
│       ├── graph_builder.py   # Graph construction (NetworkX)
│       ├── query_engine.py    # Permission analysis engine
│       ├── visualizer.py      # Graph visualization (Graphviz/matplotlib)
│       ├── models.py          # Data models and classes
│       └── utils.py           # Utility functions
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── test_models.py         # Model tests
│   ├── test_query_engine.py   # Query engine tests
│   ├── test_cli.py            # CLI tests
│   └── conftest.py            # Pytest configuration (if needed)
├── examples/                  # Usage examples
│   ├── basic_usage.py         # Programmatic usage example
│   ├── README.md              # Example documentation
│   └── examples.md            # Comprehensive examples
├── docs/                      # Documentation (future)
├── pyproject.toml             # Project configuration and dependencies
├── README.md                  # Main project documentation
├── CONTRIBUTING.md            # This file
├── LICENSE                    # MIT License
└── CHANGELOG.md               # Release history
```

### Key Components

- **`fetcher.py`**: Handles AWS API calls using boto3 to retrieve IAM data
- **`models.py`**: Defines data structures for users, roles, groups, policies, and graphs
- **`graph_builder.py`**: Constructs NetworkX graphs from IAM data
- **`query_engine.py`**: Core logic for permission analysis and queries
- **`visualizer.py`**: Generates visual representations of IAM relationships
- **`cli.py`**: Command-line interface with subcommands for all functionality
- **`utils.py`**: Helper functions for ARN parsing, security analysis, etc.

---

## Testing

### Running Tests

We use pytest for testing. Run the full test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src/iam_explorer --cov-report=term-missing tests/

# Run specific test file
pytest tests/test_query_engine.py

# Run specific test
pytest tests/test_query_engine.py::TestQueryEngine::test_who_can_do_basic

# Run with verbose output
pytest -v tests/

# Generate HTML coverage report
pytest --cov=src/iam_explorer --cov-report=html tests/
open htmlcov/index.html  # View coverage report
```

### Writing Tests

When adding new features, please include tests. Follow these guidelines:

1. **Test Structure**: Use the existing test structure in `tests/`
2. **Naming**: Test files should be named `test_<module>.py`
3. **Test Classes**: Group related tests in classes like `TestQueryEngine`
4. **Test Methods**: Name test methods descriptively: `test_who_can_do_with_wildcard`

Example test structure:

```python
import pytest
from iam_explorer.query_engine import QueryEngine
from iam_explorer.models import IAMGraph

class TestNewFeature:
    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        # Setup test data
        return graph

    def test_new_functionality(self, sample_graph):
        """Test the new functionality."""
        engine = QueryEngine(sample_graph)
        result = engine.new_method()
        assert result is not None
        assert len(result) > 0
```

### Mocking AWS Services

We use [moto](https://github.com/getmoto/moto) for AWS service mocking in tests:

```python
import boto3
import pytest
from moto import mock_iam
from iam_explorer.fetcher import IAMFetcher

@mock_iam
def test_fetch_users():
    """Test fetching users with mocked IAM."""
    # Create mock IAM resources
    iam = boto3.client('iam', region_name='us-east-1')
    iam.create_user(UserName='test-user')

    # Test the fetcher
    fetcher = IAMFetcher()
    users = fetcher.fetch_users()

    assert len(users) == 1
    assert users[0]['name'] == 'test-user'
```

### Test Data

For consistent testing, use the sample data in `examples/basic_usage.py` or create fixtures:

```python
@pytest.fixture
def sample_iam_data():
    """Provide sample IAM data for testing."""
    return {
        "users": [...],
        "roles": [...],
        "policies": [...]
    }
```

---

## Code Quality

### Coding Style

We follow Python best practices and use automated tools to maintain code quality:

1. **Code Formatting**: We use [Black](https://black.readthedocs.io/) for consistent formatting:
   ```bash
   # Format all code
   black src/iam_explorer tests examples

   # Check formatting without making changes
   black --check src/iam_explorer tests examples
   ```

2. **Linting**: We use [flake8](https://flake8.pycqa.org/) for style and error checking:
   ```bash
   # Run linter
   flake8 src/iam_explorer tests

   # With specific configuration
   flake8 --max-line-length=88 --extend-ignore=E203,W503 src/iam_explorer tests
   ```

3. **Import Sorting**: We use [isort](https://pycqa.github.io/isort/) for import organization:
   ```bash
   # Sort imports
   isort src/iam_explorer tests examples

   # Check import sorting
   isort --check-only src/iam_explorer tests examples
   ```

4. **Code Quality Check Script**:
   ```bash
   # Run all quality checks
   ./scripts/check_quality.sh  # If we create this script

   # Or manually:
   black --check src/iam_explorer tests examples
   flake8 src/iam_explorer tests
   isort --check-only src/iam_explorer tests examples
   mypy src/iam_explorer
   ```

### Type Hints

We use type hints throughout the codebase for better code clarity and IDE support:

```python
from typing import Dict, List, Optional, Set, Any
from datetime import datetime

def process_users(users: List[Dict[str, Any]]) -> Dict[str, IAMUser]:
    """Process user data and return user objects."""
    result: Dict[str, IAMUser] = {}
    for user_data in users:
        user = IAMUser(
            arn=user_data['arn'],
            name=user_data['name'],
            user_id=user_data['user_id']
        )
        result[user.arn] = user
    return result
```

**Type Checking**: We use [mypy](http://mypy-lang.org/) for static type checking:

```bash
# Run type checking
mypy src/iam_explorer

# Run with specific configuration
mypy --strict src/iam_explorer
```

### Documentation

1. **Docstrings**: Use Google-style docstrings for all public functions and classes:

```python
def who_can_do(self, action: str, resource: str = "*") -> List[Dict[str, Any]]:
    """
    Find all entities that can perform a specific action.

    Args:
        action: AWS action (e.g., 's3:GetObject', 's3:*')
        resource: Resource ARN or pattern (default: '*')

    Returns:
        List of entities that can perform the action

    Raises:
        ValueError: If action is invalid

    Example:
        >>> engine = QueryEngine(graph)
        >>> results = engine.who_can_do('s3:GetObject')
        >>> print(f"Found {len(results)} entities")
    """
```

2. **Comments**: Use comments sparingly, focusing on explaining "why" rather than "what":

```python
# Check for explicit deny first - deny always wins in AWS IAM
if self._policy_denies_action(policy, action, resource):
    is_denied = True
```

3. **README Updates**: Update documentation when adding new features or changing behavior.

---

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/) for consistent commit messages and automated releases:

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- **feat**: New feature for the user
- **fix**: Bug fix for the user
- **docs**: Documentation changes
- **style**: Code style changes (formatting, missing semicolons, etc.)
- **refactor**: Code refactoring without changing functionality
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **build**: Changes to build system or dependencies
- **ci**: Changes to CI configuration
- **chore**: Other changes that don't modify src or test files

### Scopes

Use these scopes to indicate which part of the codebase is affected:

- **fetcher**: AWS data fetching functionality
- **query**: Permission analysis and query engine
- **graph**: Graph building and manipulation
- **viz**: Visualization features
- **cli**: Command-line interface
- **models**: Data models and structures
- **utils**: Utility functions
- **tests**: Test-related changes
- **docs**: Documentation updates

### Examples

```bash
# New features
feat(query): add support for cross-account role analysis
feat(cli): add --filter option to visualize command
feat(fetcher): support for AWS Organizations data

# Bug fixes
fix(query): handle empty policy documents correctly
fix(graph): resolve circular dependency in role chains
fix(cli): improve error handling for invalid AWS credentials

# Documentation
docs(readme): update installation instructions
docs(examples): add compliance reporting examples

# Performance improvements
perf(query): optimize permission matching algorithm
perf(graph): improve memory usage for large datasets

# Breaking changes
feat(api)!: change query result format for consistency

BREAKING CHANGE: Query results now return standardized objects instead of raw dictionaries
```

### Benefits

Following this convention enables:
- **Automatic versioning**: Semantic version bumps based on commit types
- **Changelog generation**: Automated release notes
- **Better collaboration**: Clear understanding of changes
- **Release automation**: Streamlined release process

---

## Pull requests

1. Branching
   - Create a feature branch from `main`, e.g. `git checkout -b feat/trust-graph`.
   - Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
2. Open a Pull Request
    - Clearly describe **what** your change does, **why** it’s needed, and any specific feedback you’re looking for.
    - Reference any related issues, if applicable.
3. Code Review
    - Expect feedback or requests for changes from the maintainers or community.
    - Keep discussions constructive and on-topic.

---

## Release process
We use [python-semantic-release](https://github.com/python-semantic-release/python-semantic-release) to automate:
- Version bumps (based on commit messages).
- Updating `CHANGELOG.md`.
- Publishing new packages to PyPI.
- Creating GitHub releases/tags.

**How it works**:
1. When PRs are merged into `main` with commit messages that have `feat:` or `fix:` (etc.), our GitHub Actions workflow will parse these commits.
2. If a release is triggered, semantic-release updates `__version__`, the `CHANGELOG.md`, tags the release, and publishes to PyPI automatically.

---

## Feature Development Guidelines

### Adding New Query Types

When adding new query capabilities:

1. **Update Models**: Add new data structures in `models.py` if needed
2. **Extend Query Engine**: Add methods to `QueryEngine` class in `query_engine.py`
3. **Update CLI**: Add new commands or options in `cli.py`
4. **Add Tests**: Create comprehensive tests for new functionality
5. **Update Documentation**: Add examples to `examples.md`

Example workflow for adding a new query:

```python
# 1. Add method to QueryEngine
def find_privilege_escalation_paths(self, start_entity: str) -> List[List[str]]:
    """Find potential privilege escalation paths."""
    # Implementation here
    pass

# 2. Add CLI command
@query.command('escalation-paths')
@click.argument('entity_name')
def escalation_paths(entity_name: str):
    """Find privilege escalation paths for an entity."""
    # CLI implementation here
    pass

# 3. Add tests
def test_find_privilege_escalation_paths(self, sample_graph):
    """Test privilege escalation path detection."""
    # Test implementation here
    pass
```

### Adding New Visualization Features

For visualization enhancements:

1. **Extend Visualizer**: Add methods to `GraphVisualizer` class
2. **Support Multiple Formats**: Consider DOT, PNG, SVG outputs
3. **Add Filtering Options**: Allow users to focus on specific entities
4. **Update CLI**: Add visualization options to `visualize` command

### Performance Considerations

- **Large Graphs**: Test with accounts having 1000+ IAM entities
- **Memory Usage**: Monitor memory consumption with large datasets
- **Query Optimization**: Optimize graph traversal algorithms
- **Caching**: Consider caching expensive operations

---

## Security Considerations

### Handling AWS Credentials

- **Never log credentials**: Ensure AWS credentials are never logged or printed
- **Use IAM roles**: Prefer IAM roles over long-term access keys
- **Least privilege**: Request minimal IAM permissions needed for functionality
- **Secure storage**: Follow AWS best practices for credential storage

### Data Sensitivity

- **IAM data is sensitive**: Treat IAM configurations as confidential
- **Temporary files**: Clean up temporary files containing IAM data
- **Output sanitization**: Be careful about what information is displayed in logs

### Required IAM Permissions

The tool requires these IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListGroups",
                "iam:ListPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedGroupPolicies",
                "iam:ListUserPolicies",
                "iam:ListRolePolicies",
                "iam:ListGroupPolicies",
                "iam:GetUserPolicy",
                "iam:GetRolePolicy",
                "iam:GetGroupPolicy",
                "iam:GetPolicyVersion",
                "iam:ListGroupsForUser"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Performance Guidelines

### Optimization Tips

1. **Graph Size**: For large environments (1000+ entities), consider:
   - Using filters to focus on specific entities
   - Excluding AWS managed policies unless needed
   - Implementing pagination for large result sets

2. **Memory Management**:
   - Use generators for large datasets
   - Clean up temporary objects
   - Consider streaming for very large graphs

3. **Query Performance**:
   - Cache frequently accessed data
   - Optimize graph traversal algorithms
   - Use appropriate data structures (sets vs lists)

### Benchmarking

When making performance changes:

```bash
# Time CLI operations
time iam-explorer fetch --output large_account.json
time iam-explorer build-graph --input large_account.json --output large_graph.pkl
time iam-explorer query who-can-do "*" --graph large_graph.pkl

# Memory profiling (if memory_profiler is installed)
mprof run iam-explorer build-graph --input large_account.json --output large_graph.pkl
mprof plot
```

---

## Getting Help

### Documentation

- **README.md**: Basic usage and installation
- **examples.md**: Comprehensive examples and use cases
- **This file**: Development guidelines and contribution process

### Community

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For questions and community support
- **Pull Requests**: For code contributions and improvements

### Maintainer Contact

- **GitHub**: [@Saff-Buraq-Dev](https://github.com/Saff-Buraq-Dev)
- **Email**: gharbi.safwen@hotmail.com

### Getting Started Checklist

- [ ] Read this contributing guide
- [ ] Set up development environment
- [ ] Run existing tests successfully
- [ ] Try the basic example
- [ ] Explore the codebase
- [ ] Pick an issue or feature to work on
- [ ] Ask questions if needed

---

**Thank you for contributing to IAM Explorer!** 🚀

Together, we can build a powerful tool to help the community understand and secure AWS IAM configurations. Every contribution, whether it's code, documentation, bug reports, or feature suggestions, helps make IAM Explorer better for everyone.