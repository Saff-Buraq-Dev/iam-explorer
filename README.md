# iam-explorer

[![codecov](https://codecov.io/github/Saff-Buraq-Dev/iam-explorer/graph/badge.svg?token=GZ5WBX0MN5)](https://codecov.io/github/Saff-Buraq-Dev/iam-explorer)
[![CI](https://github.com/Saff-Buraq-Dev/iam-explorer/actions/workflows/ci.yaml/badge.svg)](https://github.com/Saff-Buraq-Dev/iam-explorer/actions)
[![PyPI](https://img.shields.io/pypi/v/iam-explorer.svg)](https://pypi.org/project/iam-explorer/)

**iam-explorer** is a Python CLI tool that builds and visualizes AWS IAM relationships between users, roles, policies, and more. It also allows you to query “which user or role can perform a specific action?” while considering role chaining, permission boundaries, and trust relationships.

## Features

- **🔄 Dynamic AWS Actions**: Automatically fetches latest service actions from AWS Policy Generator (420+ services)
- **🔍 Advanced Pattern Matching**: Supports complex wildcards like `s3:Get*`, `*:Create*`, `ec2:Describe*`
- **📊 Comprehensive Analysis**: Query permissions across all AWS services with real-time action definitions
- **🎯 Smart Queries**: Natural language questions like "Who can perform action X?" and "What can user Y do?"
- **📈 Graph Visualization**: Interactive relationship mapping using Graphviz and matplotlib
- **🔗 Role Assumption Chains**: Tracks complex role inheritance and cross-account access
- **🛡️ Security-First**: Handles permission boundaries, inline policies, and Allow/Deny evaluation
- **⚡ High Performance**: Efficient graph algorithms for large AWS environments
- **🔧 Developer-Friendly**: Both CLI and Python API for automation and integration

## Installation

To install from PyPI, simply run:

```bash
pip install iam-explorer
```

*(Requires Python 3.10–3.13.)*

## Quick Start

### 1. Installation

```bash
# Install from source
git clone https://github.com/Saff-Buraq-Dev/iam-explorer.git
cd iam-explorer
pip install -e .

# Verify installation
iam-explorer --help
```

### 2. Basic Workflow

```bash
# Step 1: Fetch IAM data from your AWS account
iam-explorer fetch --output iam_data.json

# Step 2: Build a graph representation
iam-explorer build-graph --input iam_data.json --output iam_graph.pkl

# Step 3: Start querying!
iam-explorer query who-can-do "s3:GetObject"
iam-explorer query what-can-do my-user-name
```

### 3. Key Features Demo

```bash
# 🔍 Security Analysis
iam-explorer query who-can-do "*"                    # Find admin users
iam-explorer query who-can-do "iam:*"                # Who can manage IAM?
iam-explorer query who-can-do "*:Delete*"            # Who can delete resources?

# 👤 User/Role Analysis
iam-explorer query what-can-do suspicious-user       # Audit specific user
iam-explorer query what-can-do lambda-execution-role # Check role permissions

# 🎯 Advanced Pattern Matching (NEW!)
iam-explorer query who-can-do "s3:Get*"             # All S3 read operations
iam-explorer query who-can-do "ec2:Describe*"       # All EC2 describe actions
iam-explorer query who-can-do "*:Create*"           # All create permissions

# 📊 Visualization
iam-explorer visualize --output iam_graph.dot       # Generate graph
iam-explorer visualize --filter my-user --output focused.dot  # Focus on specific entities

# 📋 Export for Analysis
iam-explorer query who-can-do "*" --format json > admin_users.json
```

### 4. Advanced Features

- **Dynamic AWS Actions**: Automatically fetches latest AWS service actions from AWS Policy Generator
- **Pattern Matching**: Supports complex wildcards like `s3:Get*`, `*:Create*`, `ec2:Describe*`
- **Cross-Service Analysis**: Find permissions across all 420+ AWS services
- **Role Assumption Chains**: Tracks who can assume roles and inheritance
- **Permission Boundaries**: Handles permission boundary policies
- **Visualization**: Generate interactive graphs with filtering options

### 5. Real-World Examples

The [`examples/`](examples/) directory contains production-ready scripts for:

- **[Security Auditing](examples/security_audit.py)**: Comprehensive security analysis with risk scoring
- **[Compliance Reporting](examples/compliance_report.py)**: SOX, PCI DSS, and GDPR compliance checks
- **[Incident Response](examples/incident_response.py)**: Blast radius analysis and containment guidance
- **[Automation & Monitoring](examples/automation_scripts.py)**: Daily monitoring with Slack/email alerts
- **[CLI Examples](examples/cli_examples.sh)**: Complete command reference and workflows

Each script is production-ready and includes detailed documentation and usage examples.

## Programmatic Usage

You can also use IAM Explorer as a Python library:

```python
from iam_explorer.fetcher import IAMFetcher
from iam_explorer.graph_builder import GraphBuilder
from iam_explorer.query_engine import QueryEngine

# Fetch IAM data
fetcher = IAMFetcher(profile_name='my-profile')
data = fetcher.fetch_all_data()

# Build graph
builder = GraphBuilder()
graph = builder.build_from_data(data)

# Query permissions
engine = QueryEngine(graph)

# Find who can perform an action
results = engine.who_can_do('s3:GetObject')
for result in results:
    print(f"{result['type']}: {result['name']}")

# Find what an entity can do
permissions = engine.what_can_entity_do('my-user')
print(f"User has {len(permissions['effective_actions'])} permissions")
```

## Architecture

IAM Explorer consists of several key components:

- **Fetcher**: Retrieves IAM data from AWS APIs using boto3
- **Graph Builder**: Constructs a NetworkX graph of IAM relationships
- **Query Engine**: Analyzes permissions and answers queries about access
- **Visualizer**: Generates visual representations using Graphviz and matplotlib
- **CLI**: Provides a command-line interface for all functionality

The tool handles complex IAM scenarios including:
- Role assumption chains
- Permission boundaries
- Inline vs managed policies
- Cross-account access patterns
- Allow/Deny policy evaluation

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development workflow, how to run tests, and how to submit pull requests.

## License

This project is licensed under the terms of the [Apache License](./LICENSE).

## Acknowledgments

- [Boto3](https://github.com/boto/boto3)
- [Graphviz](https://graphviz.org/)
- [NetworkX](https://networkx.org/)
- [python-semantic-release](https://github.com/python-semantic-release/python-semantic-release)
