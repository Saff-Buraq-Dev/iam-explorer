#!/usr/bin/env python3
"""
Security Audit Example for IAM Explorer

This script demonstrates how to perform comprehensive security audits
using IAM Explorer to identify potential security risks and violations.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add the src directory to the path so we can import iam_explorer
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from iam_explorer.graph_builder import GraphBuilder
from iam_explorer.query_engine import QueryEngine


def load_graph(graph_file: str) -> QueryEngine:
    """Load IAM graph and return query engine."""
    if not Path(graph_file).exists():
        print(f"❌ Graph file '{graph_file}' not found.")
        print("Run: iam-explorer fetch && iam-explorer build-graph")
        sys.exit(1)
    
    builder = GraphBuilder()
    graph = builder.load_graph(graph_file)
    return QueryEngine(graph)


def security_audit(engine: QueryEngine) -> dict:
    """Perform comprehensive security audit."""
    print("🔍 Starting IAM Security Audit...")
    
    audit_results = {
        "timestamp": datetime.now().isoformat(),
        "findings": [],
        "recommendations": [],
        "statistics": {}
    }
    
    # 1. Find all admin users
    print("\n1. Checking for administrative access...")
    admin_entities = engine.who_can_do('*')
    audit_results["statistics"]["admin_entities"] = len(admin_entities)
    
    if len(admin_entities) > 5:
        audit_results["findings"].append({
            "severity": "HIGH",
            "category": "Excessive Admin Access",
            "description": f"Found {len(admin_entities)} entities with administrative access",
            "entities": [e['name'] for e in admin_entities],
            "recommendation": "Review and reduce administrative access to essential personnel only"
        })
    
    # 2. Check IAM management permissions
    print("2. Checking IAM management permissions...")
    iam_managers = engine.who_can_do('iam:*')
    audit_results["statistics"]["iam_managers"] = len(iam_managers)
    
    if len(iam_managers) > 3:
        audit_results["findings"].append({
            "severity": "HIGH",
            "category": "IAM Management Access",
            "description": f"Found {len(iam_managers)} entities that can manage IAM",
            "entities": [e['name'] for e in iam_managers],
            "recommendation": "Limit IAM management permissions to security team only"
        })
    
    # 3. Check for dangerous delete permissions
    print("3. Checking for dangerous delete permissions...")
    delete_entities = engine.who_can_do('*:Delete*')
    audit_results["statistics"]["delete_permissions"] = len(delete_entities)
    
    if len(delete_entities) > 10:
        audit_results["findings"].append({
            "severity": "MEDIUM",
            "category": "Broad Delete Permissions",
            "description": f"Found {len(delete_entities)} entities with delete permissions",
            "recommendation": "Review delete permissions and implement least privilege"
        })
    
    # 4. Check S3 bucket deletion specifically
    print("4. Checking S3 bucket deletion permissions...")
    s3_delete_bucket = engine.who_can_do('s3:DeleteBucket')
    audit_results["statistics"]["s3_delete_bucket"] = len(s3_delete_bucket)
    
    if len(s3_delete_bucket) > 2:
        audit_results["findings"].append({
            "severity": "HIGH",
            "category": "S3 Bucket Deletion",
            "description": f"Found {len(s3_delete_bucket)} entities that can delete S3 buckets",
            "entities": [e['name'] for e in s3_delete_bucket],
            "recommendation": "Restrict S3 bucket deletion to backup/disaster recovery roles only"
        })
    
    # 5. Check for cross-service create permissions
    print("5. Checking cross-service create permissions...")
    create_entities = engine.who_can_do('*:Create*')
    audit_results["statistics"]["create_permissions"] = len(create_entities)
    
    # 6. Check secrets access
    print("6. Checking secrets access...")
    secrets_access = engine.who_can_do('secretsmanager:GetSecretValue')
    audit_results["statistics"]["secrets_access"] = len(secrets_access)
    
    if len(secrets_access) > 5:
        audit_results["findings"].append({
            "severity": "MEDIUM",
            "category": "Secrets Access",
            "description": f"Found {len(secrets_access)} entities that can access secrets",
            "recommendation": "Review secrets access and implement rotation policies"
        })
    
    # 7. Check KMS key access
    print("7. Checking KMS key access...")
    kms_access = engine.who_can_do('kms:Decrypt')
    audit_results["statistics"]["kms_access"] = len(kms_access)
    
    # Generate overall recommendations
    if len(audit_results["findings"]) == 0:
        audit_results["recommendations"].append("✅ No major security violations detected")
    else:
        audit_results["recommendations"].extend([
            "🔒 Implement least privilege access principles",
            "📋 Conduct regular access reviews",
            "🔄 Set up automated monitoring for permission changes",
            "📝 Document and justify all administrative access"
        ])
    
    return audit_results


def print_audit_results(results: dict):
    """Print audit results in a readable format."""
    print("\n" + "="*60)
    print("🛡️  IAM SECURITY AUDIT REPORT")
    print("="*60)
    
    print(f"\n📊 Statistics:")
    for key, value in results["statistics"].items():
        print(f"   • {key.replace('_', ' ').title()}: {value}")
    
    if results["findings"]:
        print(f"\n⚠️  Security Findings ({len(results['findings'])}):")
        for i, finding in enumerate(results["findings"], 1):
            severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
            emoji = severity_emoji.get(finding["severity"], "⚪")
            
            print(f"\n   {i}. {emoji} {finding['category']} ({finding['severity']})")
            print(f"      {finding['description']}")
            print(f"      💡 {finding['recommendation']}")
            
            if "entities" in finding and len(finding["entities"]) <= 10:
                print(f"      📋 Entities: {', '.join(finding['entities'])}")
            elif "entities" in finding:
                print(f"      📋 Entities: {', '.join(finding['entities'][:5])} ... and {len(finding['entities'])-5} more")
    
    print(f"\n💡 Recommendations:")
    for rec in results["recommendations"]:
        print(f"   • {rec}")
    
    print(f"\n📅 Report generated: {results['timestamp']}")
    print("="*60)


def main():
    """Main function."""
    # Default graph file
    graph_file = "iam_graph.pkl"
    
    # Check if custom graph file provided
    if len(sys.argv) > 1:
        graph_file = sys.argv[1]
    
    # Load graph and perform audit
    engine = load_graph(graph_file)
    results = security_audit(engine)
    
    # Print results
    print_audit_results(results)
    
    # Save results to file
    output_file = f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    
    # Exit with error code if high severity findings
    high_severity_count = sum(1 for f in results["findings"] if f["severity"] == "HIGH")
    if high_severity_count > 0:
        print(f"\n❌ Audit completed with {high_severity_count} high-severity findings")
        sys.exit(1)
    else:
        print(f"\n✅ Audit completed successfully")


if __name__ == "__main__":
    main()
