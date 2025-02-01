# Contributing to iam-explorer

First off, thanks for taking the time to contribute! This document outlines our guidelines and best practices for contributing to **iam-explorer**.

## Table of contents
- [Contributing to iam-explorer](#contributing-to-iam-explorer)
  - [Table of contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Development environment](#development-environment)
  - [Testing](#testing)
    - [Mocking AWS](#mocking-aws)
  - [Coding style](#coding-style)
  - [Commit messages](#commit-messages)
    - [Examples](#examples)
  - [Pull requests](#pull-requests)
  - [Release process](#release-process)
  - [Contact](#contact)

---

## Getting Started

1. **Fork and Clone**  
   - [Fork the repository](https://github.com/YOUR_USERNAME/iam-explorer/fork)  
   - Clone your fork locally:
     ```bash
     git clone https://github.com/YOUR_USERNAME/iam-explorer.git
     cd iam-explorer
     ```
2. **Set Up Remotes**  
   - Add the original repository as an upstream remote:
     ```bash
     git remote add upstream https://github.com/ORIGINAL_OWNER/iam-explorer.git
     ```
   - Keep your local fork in sync with upstream by periodically pulling changes.

3. **Choose or Create an Issue**  
   - Check the [issue tracker](https://github.com/YOUR_USERNAME/iam-explorer/issues) to see if your issue or feature request is already being discussed. If not, feel free to open a new one.

---

## Development environment

**iam-explorer** supports Python 3.10 to 3.13. We recommend using a virtual environment:

1. **Create and activate a virtual environment**:
   ```bash
   python3.13 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # .\venv\Scripts\activate  # On Windows
    ```
2. **Install dependencies**:
    ```bash
    pip install --upgrade pip
    pip install -e .[dev]
    ```
    This will install both runtime and dev/test dependencies (e.g., pytest, flake8).

---

## Project structure

A brief overview of the repo layout:

```bash
iam-explorer/
├── .github/
│   └── workflows/
│       └── ci.yaml
├── src/
│   └── iam_explorer/
│       ├── __init__.py
│       ├── cli.py
│       ├── fetch.py
│       ├── graph.py
│       ├── query.py
│       ├── visualize.py
│       └── utils.py
├── tests/
│   ├── test_cli.py
│   ├── test_fetch.py
│   ├── test_graph.py
│   ├── test_query.py
│   └── test_visualize.py
├── CHANGELOG.md
├── pyproject.toml
├── LICENSE
├── README.md
└── CONTRIBUTING.md
```

- `src/iam-explorer/`: Python package source files.
- `tests/`: Unit tests for each module.
- `pyproject.toml`: Declares project metadata and dependencies.
- `CHANGELOG.md`: Auto-generated/updated by semantic-release.

---

## Testing

To run tests, use:
```bash
pytest --cov=src/iam_explorer --cov-report=term tests
```
You can also view an HTML coverage report:
```bash
pytest --cov=src/iam_explorer --cov-report=html tests
open htmlcov/index.html
```

### Mocking AWS
**iam-explorer** interacts with AWS. We use [moto](https://github.com/getmoto/moto) for AWS mocking in tests. This allows you to test locally without hitting real AWS services.

---

## Coding style
1. **Linters & formatters**:
    - We use [flake8](https://github.com/pycqa/flake8) to enforce coding standards:
    ```bash
    flake8 src/iam_explorer tests
    ```
    - We use [black]() for formatting:
    ```bash
    black src/iam_explorer tests
    ```

2. **PEP 8**:
    - Follow [PEP 8](https://peps.python.org/pep-0008/) guidelines for code style where possible.

---

## Commit messages
We use **semantic-release** with the Conventional Commits style. This means commit messages should follow this format:

```bash
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

- Type: Must be one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, or `chore`.
- Scope (optional): A quick label for the part of the codebase affected (e.g., `fetch`, `cli`, `docs`, etc.).
- Description: A short, imperative description of the change.
- Body (optional): Longer explanation if needed.
- Footer (optional): For breaking changes (`BREAKING CHANGE:`), referencing issues (`Closes #123`), etc.

### Examples
- **Feature**: `feat(fetch): add new subcommand to gather role data`
- **Fix**: `fix(graph): correct edge case when role has no trust policy`

Following this ensures:
- Automatic version bump (major, minor, patch).
- Automatic changelog updates.

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
## Contact
- Issues: For bugs and feature requests, please open a GitHub Issue.
- Pull Requests: PRs are welcome!
- Email: If you need to reach out privately, you can [email me](sgharbi@gharbidev.com).

---
**Thank you for contributing to iam-explorer!**
Together, we can build a powerful tool to visualize AWS IAM relationships and help the community manage and understand AWS permissions more effectively.