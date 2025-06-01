#!/usr/bin/env python3
"""
Basic usage example for IAM Explorer.

This script demonstrates how to use IAM Explorer programmatically
to analyze IAM permissions and relationships.
"""

import json
import logging
from pathlib import Path

from iam_explorer.models import IAMUser, IAMRole, IAMPolicy, IAMGraph
from iam_explorer.graph_builder import GraphBuilder
from iam_explorer.query_engine import QueryEngine
from iam_explorer.visualizer import GraphVisualizer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_sample_data():
    """Create sample IAM data for demonstration."""
    return {
        "users": [
            {
                "arn": "arn:aws:iam::123456789012:user/alice",
                "name": "alice",
                "user_id": "AIDAEXAMPLE123456789",
                "path": "/",
                "create_date": "2023-01-01T00:00:00",
                "attached_policies": [
                    "arn:aws:iam::123456789012:policy/s3-read-only",
                    "arn:aws:iam::123456789012:policy/ec2-describe"
                ],
                "inline_policies": {},
                "groups": ["developers"],
                "tags": []
            },
            {
                "arn": "arn:aws:iam::123456789012:user/bob",
                "name": "bob",
                "user_id": "AIDAEXAMPLE987654321",
                "path": "/",
                "create_date": "2023-01-01T00:00:00",
                "attached_policies": [],
                "inline_policies": {
                    "inline-s3-policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "arn:aws:s3:::my-bucket/*"
                            }
                        ]
                    }
                },
                "groups": ["admins"],
                "tags": []
            }
        ],
        "roles": [
            {
                "arn": "arn:aws:iam::123456789012:role/ec2-instance-role",
                "name": "ec2-instance-role",
                "role_id": "AROAEXAMPLE123456789",
                "path": "/",
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                },
                "create_date": "2023-01-01T00:00:00",
                "attached_policies": ["arn:aws:iam::123456789012:policy/s3-read-only"],
                "inline_policies": {},
                "tags": []
            },
            {
                "arn": "arn:aws:iam::123456789012:role/lambda-execution-role",
                "name": "lambda-execution-role",
                "role_id": "AROAEXAMPLE987654321",
                "path": "/",
                "assume_role_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        },
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                },
                "create_date": "2023-01-01T00:00:00",
                "attached_policies": ["arn:aws:iam::123456789012:policy/admin-access"],
                "inline_policies": {},
                "tags": []
            }
        ],
        "groups": [
            {
                "arn": "arn:aws:iam::123456789012:group/developers",
                "name": "developers",
                "group_id": "AGPAEXAMPLE123456789",
                "path": "/",
                "create_date": "2023-01-01T00:00:00",
                "attached_policies": ["arn:aws:iam::123456789012:policy/ec2-describe"],
                "inline_policies": {}
            },
            {
                "arn": "arn:aws:iam::123456789012:group/admins",
                "name": "admins",
                "group_id": "AGPAEXAMPLE987654321",
                "path": "/",
                "create_date": "2023-01-01T00:00:00",
                "attached_policies": ["arn:aws:iam::123456789012:policy/admin-access"],
                "inline_policies": {}
            }
        ],
        "policies": [
            {
                "arn": "arn:aws:iam::123456789012:policy/s3-read-only",
                "name": "s3-read-only",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": "*"
                        }
                    ]
                },
                "is_aws_managed": False,
                "create_date": "2023-01-01T00:00:00",
                "update_date": "2023-01-01T00:00:00"
            },
            {
                "arn": "arn:aws:iam::123456789012:policy/ec2-describe",
                "name": "ec2-describe",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["ec2:Describe*"],
                            "Resource": "*"
                        }
                    ]
                },
                "is_aws_managed": False,
                "create_date": "2023-01-01T00:00:00",
                "update_date": "2023-01-01T00:00:00"
            },
            {
                "arn": "arn:aws:iam::123456789012:policy/admin-access",
                "name": "admin-access",
                "policy_document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                },
                "is_aws_managed": False,
                "create_date": "2023-01-01T00:00:00",
                "update_date": "2023-01-01T00:00:00"
            }
        ],
        "metadata": {
            "fetch_time": "2023-01-01T00:00:00",
            "profile": "example",
            "region": "us-east-1"
        }
    }


def main():
    """Main example function."""
    logger.info("IAM Explorer Basic Usage Example")
    logger.info("=" * 40)
    
    # Create sample data
    logger.info("Creating sample IAM data...")
    sample_data = create_sample_data()
    
    # Save sample data to file
    data_file = "sample_iam_data.json"
    with open(data_file, 'w') as f:
        json.dump(sample_data, f, indent=2)
    logger.info(f"Sample data saved to {data_file}")
    
    # Build graph from data
    logger.info("Building IAM graph...")
    builder = GraphBuilder()
    graph = builder.build_from_data(sample_data)
    
    # Save graph
    graph_file = "sample_iam_graph.pkl"
    builder.save_graph(graph_file)
    logger.info(f"Graph saved to {graph_file}")
    
    # Create query engine
    logger.info("Creating query engine...")
    engine = QueryEngine(graph)
    
    # Example queries
    logger.info("\n" + "=" * 40)
    logger.info("EXAMPLE QUERIES")
    logger.info("=" * 40)
    
    # Query 1: Who can read S3 objects?
    logger.info("\n1. Who can perform 's3:GetObject'?")
    results = engine.who_can_do("s3:GetObject")
    for result in results:
        logger.info(f"   - {result['type'].upper()}: {result['name']}")
        if result['type'] == 'role' and result.get('can_be_assumed_by'):
            logger.info(f"     Can be assumed by: {', '.join(result['can_be_assumed_by'])}")
    
    # Query 2: What can Alice do?
    logger.info("\n2. What can user 'alice' do?")
    result = engine.what_can_entity_do("alice")
    if 'error' not in result:
        logger.info(f"   Entity: {result['entity_name']} ({result['entity_type']})")
        logger.info(f"   Effective actions: {len(result['effective_actions'])}")
        for action in result['effective_actions'][:5]:  # Show first 5
            logger.info(f"     - {action}")
        if len(result['effective_actions']) > 5:
            logger.info(f"     ... and {len(result['effective_actions']) - 5} more")
    else:
        logger.info(f"   Error: {result['error']}")
    
    # Query 3: Who has admin access?
    logger.info("\n3. Who can perform any action ('*')?")
    results = engine.who_can_do("*")
    for result in results:
        logger.info(f"   - {result['type'].upper()}: {result['name']}")
    
    # Query 4: What can the lambda execution role do?
    logger.info("\n4. What can role 'lambda-execution-role' do?")
    result = engine.what_can_entity_do("lambda-execution-role")
    if 'error' not in result:
        logger.info(f"   Entity: {result['entity_name']} ({result['entity_type']})")
        logger.info(f"   Effective actions: {len(result['effective_actions'])}")
        if result.get('assumable_roles'):
            logger.info(f"   Can assume: {', '.join(result['assumable_roles'])}")
    else:
        logger.info(f"   Error: {result['error']}")
    
    # Generate visualization
    logger.info("\n" + "=" * 40)
    logger.info("GENERATING VISUALIZATION")
    logger.info("=" * 40)
    
    visualizer = GraphVisualizer(graph)
    
    # Generate DOT file
    dot_file = "sample_iam_graph.dot"
    visualizer.generate_dot(dot_file)
    logger.info(f"DOT visualization saved to {dot_file}")
    logger.info("To convert to PNG: dot -Tpng sample_iam_graph.dot -o sample_iam_graph.png")
    
    # Show graph statistics
    stats = visualizer.get_graph_stats()
    logger.info(f"\nGraph Statistics:")
    logger.info(f"  - Total nodes: {stats['total_nodes']}")
    logger.info(f"  - Total edges: {stats['total_edges']}")
    logger.info(f"  - Users: {stats['users']}")
    logger.info(f"  - Roles: {stats['roles']}")
    logger.info(f"  - Groups: {stats['groups']}")
    logger.info(f"  - Policies: {stats['policies']}")
    
    logger.info("\n" + "=" * 40)
    logger.info("Example completed successfully!")
    logger.info("Files created:")
    logger.info(f"  - {data_file}")
    logger.info(f"  - {graph_file}")
    logger.info(f"  - {dot_file}")


if __name__ == "__main__":
    main()
