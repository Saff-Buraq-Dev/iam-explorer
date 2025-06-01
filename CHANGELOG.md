# CHANGELOG


## v0.2.0 (2025-06-01)

### Bug Fixes

- Resolve GitHub Actions CI failure with pygraphviz
  ([`86bf222`](https://github.com/Saff-Buraq-Dev/iam-explorer/commit/86bf222c252ae31481bab75b94f6f910d1a4ead4))

- Make pygraphviz an optional dependency in [visualization] extra - Add system dependencies
  (graphviz, graphviz-dev, pkg-config) to CI workflow - Update visualizer to handle missing
  pygraphviz gracefully - Add proper error messages when visualization features are unavailable -
  Maintain backward compatibility for core functionality - All 62 tests passing with improved error
  handling

Fixes CI build failures caused by pygraphviz compilation issues.

### Code Style

- Fix all flake8 linting issues
  ([`0bec17e`](https://github.com/Saff-Buraq-Dev/iam-explorer/commit/0bec17ef07acb2e9735d531554359574b4d7bf18))

- Remove unused imports across all test files - Fix f-string placeholders in CLI module - Fix line
  length violations by breaking long lines - Remove trailing whitespace - Fix arithmetic operator
  spacing - Update import statements to remove unused dependencies - Maintain 62 passing tests with
  50% coverage - Code now passes flake8 linting with max-line-length=120

All tests still passing after linting fixes.

### Features

- Add fetch data
  ([`e57a96e`](https://github.com/Saff-Buraq-Dev/iam-explorer/commit/e57a96e386138dca5f21bc616a07cc043e7deab3))

- Add queries support
  ([`8a63c9e`](https://github.com/Saff-Buraq-Dev/iam-explorer/commit/8a63c9e3598821a6512b469cff4771ca33bd6850))


## v0.1.0 (2025-02-01)

### Features

- Add project structure
  ([`b87f215`](https://github.com/Saff-Buraq-Dev/iam-explorer/commit/b87f2158f0941084cb21549b8400cd8b4c4b2930))
