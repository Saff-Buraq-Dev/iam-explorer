# iam-explorer

[![codecov](https://codecov.io/github/Saff-Buraq-Dev/iam-explorer/graph/badge.svg?token=GZ5WBX0MN5)](https://codecov.io/github/Saff-Buraq-Dev/iam-explorer)
[![CI](https://github.com/Saff-Buraq-Dev/iam-explorer/actions/workflows/ci.yaml/badge.svg)](https://github.com/Saff-Buraq-Dev/iam-explorer/actions)
[![PyPI](https://img.shields.io/pypi/v/iam-explorer.svg)](https://pypi.org/project/iam-explorer/)

**iam-explorer** is a Python CLI tool that builds and visualizes AWS IAM relationships between users, roles, policies, and more. It also allows you to query “which user or role can perform a specific action?” while considering role chaining, permission boundaries, and (eventually) Service Control Policies.

## Features

- **Fetch** IAM data (users, groups, roles, policies) via AWS APIs.
- **Build** a graph representation of IAM resources and trust relationships.
- **Query** effectively who can perform a specific action, considering role chaining.
- **Visualize** the relationships using Graphviz-style diagrams.

## Installation

To install from PyPI, simply run:

```bash
pip install iam-explorer
```

*(Requires Python 3.10–3.13.)*

## Usage

Below are common commands you can run after installing:

```bash
# 1. Fetch IAM Data
iam-explorer fetch --profile my-aws-profile --region us-east-1

# 2. Build the Graph from fetched data
iam-explorer build-graph --input iam_data.json --output graph.pkl

# 3. Query who can do a specific action
iam-explorer query who-can-do s3:PutObject

# 4. Visualize the graph in DOT format
iam-explorer visualize --input graph.pkl --output iam_graph.dot
```

From there, you can convert the DOT file to PNG or other formats using:
```bash
dot -Tpng iam_graph.dot -o iam_graph.png
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development workflow, how to run tests, and how to submit pull requests.

## License

This project is licensed under the terms of the [Apache License](./LICENSE).

## Acknowledgments

- [Boto3](https://github.com/boto/boto3)
- [Graphviz](https://graphviz.org/)
- [NetworkX](https://networkx.org/)
- [python-semantic-release](https://github.com/python-semantic-release/python-semantic-release)
