#!/usr/bin/env python3
"""
Compliance Reporting Example for IAM Explorer

This script generates compliance reports for various standards like SOX, PCI DSS, and GDPR
using IAM Explorer to analyze access patterns and identify compliance violations.
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


def generate_sox_report(engine: QueryEngine) -> dict:
    """Generate SOX compliance report."""
    print("📋 Generating SOX Compliance Report...")
    
    report = {
        "standard": "SOX (Sarbanes-Oxley Act)",
        "generated_at": datetime.now().isoformat(),
        "controls": []
    }
    
    # SOX Control 1: Segregation of Duties
    print("   • Checking segregation of duties...")
    
    # Check for entities with both read and write access to financial data
    # (In real scenario, you'd filter by specific S3 buckets or resources)
    s3_readers = set(e['name'] for e in engine.who_can_do('s3:GetObject'))
    s3_writers = set(e['name'] for e in engine.who_can_do('s3:PutObject'))
    s3_deleters = set(e['name'] for e in engine.who_can_do('s3:DeleteObject'))
    
    # Find overlaps (potential SOX violations)
    read_write_overlap = s3_readers.intersection(s3_writers)
    read_delete_overlap = s3_readers.intersection(s3_deleters)
    
    sod_status = "COMPLIANT"
    sod_issues = []
    
    if read_write_overlap:
        sod_status = "NON_COMPLIANT"
        sod_issues.append(f"Entities with both read and write access: {', '.join(list(read_write_overlap)[:5])}")
    
    if read_delete_overlap:
        sod_status = "NON_COMPLIANT"
        sod_issues.append(f"Entities with both read and delete access: {', '.join(list(read_delete_overlap)[:5])}")
    
    report["controls"].append({
        "control_id": "SOX-SoD-001",
        "control_name": "Segregation of Duties",
        "description": "Ensure separation between read and write access to financial data",
        "status": sod_status,
        "issues": sod_issues,
        "remediation": "Separate read and write permissions for financial data access"
    })
    
    # SOX Control 2: Administrative Access Limitation
    print("   • Checking administrative access controls...")
    
    admins = engine.who_can_do('*')
    admin_status = "COMPLIANT" if len(admins) <= 3 else "NON_COMPLIANT"
    
    report["controls"].append({
        "control_id": "SOX-ADM-001",
        "control_name": "Administrative Access Control",
        "description": "Limit administrative access to essential personnel",
        "status": admin_status,
        "admin_count": len(admins),
        "admin_entities": [a['name'] for a in admins],
        "remediation": "Reduce number of administrative accounts to minimum required"
    })
    
    # SOX Control 3: Audit Trail Access
    print("   • Checking audit trail access...")
    
    cloudtrail_access = engine.who_can_do('cloudtrail:*')
    audit_status = "COMPLIANT" if len(cloudtrail_access) <= 2 else "REVIEW_REQUIRED"
    
    report["controls"].append({
        "control_id": "SOX-AUD-001",
        "control_name": "Audit Trail Protection",
        "description": "Protect access to audit logs and trails",
        "status": audit_status,
        "entities_with_access": len(cloudtrail_access),
        "remediation": "Limit CloudTrail access to security and compliance teams only"
    })
    
    return report


def generate_pci_report(engine: QueryEngine) -> dict:
    """Generate PCI DSS compliance report."""
    print("💳 Generating PCI DSS Compliance Report...")
    
    report = {
        "standard": "PCI DSS (Payment Card Industry Data Security Standard)",
        "generated_at": datetime.now().isoformat(),
        "requirements": []
    }
    
    # PCI Requirement 7: Restrict access to cardholder data
    print("   • Checking cardholder data access...")
    
    # Check access to payment-related resources
    s3_access = engine.who_can_do('s3:GetObject')
    dynamodb_access = engine.who_can_do('dynamodb:GetItem')
    
    report["requirements"].append({
        "requirement": "PCI DSS 7.1",
        "description": "Limit access to cardholder data by business need-to-know",
        "entities_with_s3_access": len(s3_access),
        "entities_with_db_access": len(dynamodb_access),
        "status": "REVIEW_REQUIRED",
        "recommendation": "Review and minimize access to systems containing cardholder data"
    })
    
    # PCI Requirement 8: Identify and authenticate access
    print("   • Checking authentication controls...")
    
    iam_managers = engine.who_can_do('iam:*')
    
    report["requirements"].append({
        "requirement": "PCI DSS 8.1",
        "description": "Define and implement policies for proper user identification",
        "iam_managers": len(iam_managers),
        "status": "COMPLIANT" if len(iam_managers) <= 2 else "NON_COMPLIANT",
        "recommendation": "Ensure strong authentication for all IAM management activities"
    })
    
    # PCI Requirement 3: Protect stored cardholder data
    print("   • Checking encryption key access...")
    
    kms_access = engine.who_can_do('kms:Decrypt')
    
    report["requirements"].append({
        "requirement": "PCI DSS 3.4",
        "description": "Render cardholder data unreadable (encryption)",
        "entities_with_key_access": len(kms_access),
        "status": "REVIEW_REQUIRED",
        "recommendation": "Ensure encryption keys are properly protected and access is limited"
    })
    
    return report


def generate_gdpr_report(engine: QueryEngine) -> dict:
    """Generate GDPR compliance report."""
    print("🇪🇺 Generating GDPR Compliance Report...")
    
    report = {
        "standard": "GDPR (General Data Protection Regulation)",
        "generated_at": datetime.now().isoformat(),
        "articles": []
    }
    
    # GDPR Article 32: Security of processing
    print("   • Checking data processing security...")
    
    personal_data_access = engine.who_can_do('s3:GetObject')  # Assuming PII in S3
    
    report["articles"].append({
        "article": "Article 32",
        "title": "Security of processing",
        "description": "Implement appropriate technical and organizational measures",
        "entities_with_data_access": len(personal_data_access),
        "status": "REVIEW_REQUIRED",
        "recommendation": "Implement role-based access control for personal data processing"
    })
    
    # GDPR Article 17: Right to erasure
    print("   • Checking data deletion capabilities...")
    
    deletion_access = engine.who_can_do('s3:DeleteObject')
    
    report["articles"].append({
        "article": "Article 17",
        "title": "Right to erasure ('right to be forgotten')",
        "description": "Ability to erase personal data without undue delay",
        "entities_with_deletion_rights": len(deletion_access),
        "status": "CAPABLE" if deletion_access else "NEEDS_IMPLEMENTATION",
        "recommendation": "Ensure processes exist for timely data deletion upon request"
    })
    
    # GDPR Article 25: Data protection by design and by default
    print("   • Checking access controls...")
    
    admin_access = engine.who_can_do('*')
    
    report["articles"].append({
        "article": "Article 25",
        "title": "Data protection by design and by default",
        "description": "Implement data protection principles in system design",
        "admin_entities": len(admin_access),
        "status": "REVIEW_REQUIRED",
        "recommendation": "Implement least privilege access and privacy by design principles"
    })
    
    return report


def print_compliance_report(reports: dict):
    """Print compliance reports in a readable format."""
    print("\n" + "="*70)
    print("📋 COMPLIANCE REPORT SUMMARY")
    print("="*70)
    
    for standard, report in reports.items():
        print(f"\n🔍 {report['standard']}")
        print("-" * 50)
        
        if 'controls' in report:  # SOX format
            for control in report['controls']:
                status_emoji = {"COMPLIANT": "✅", "NON_COMPLIANT": "❌", "REVIEW_REQUIRED": "⚠️"}
                emoji = status_emoji.get(control['status'], "❓")
                print(f"   {emoji} {control['control_id']}: {control['control_name']}")
                if control['status'] != "COMPLIANT":
                    print(f"      💡 {control['remediation']}")
        
        elif 'requirements' in report:  # PCI format
            for req in report['requirements']:
                status_emoji = {"COMPLIANT": "✅", "NON_COMPLIANT": "❌", "REVIEW_REQUIRED": "⚠️"}
                emoji = status_emoji.get(req['status'], "❓")
                print(f"   {emoji} {req['requirement']}: {req['description']}")
                if req['status'] != "COMPLIANT":
                    print(f"      💡 {req['recommendation']}")
        
        elif 'articles' in report:  # GDPR format
            for article in report['articles']:
                status_emoji = {"CAPABLE": "✅", "NEEDS_IMPLEMENTATION": "❌", "REVIEW_REQUIRED": "⚠️"}
                emoji = status_emoji.get(article['status'], "❓")
                print(f"   {emoji} {article['article']}: {article['title']}")
                if article['status'] != "CAPABLE":
                    print(f"      💡 {article['recommendation']}")


def main():
    """Main function."""
    # Default graph file
    graph_file = "iam_graph.pkl"
    
    # Check if custom graph file provided
    if len(sys.argv) > 1:
        graph_file = sys.argv[1]
    
    # Load graph
    engine = load_graph(graph_file)
    
    # Generate all compliance reports
    reports = {
        "sox": generate_sox_report(engine),
        "pci": generate_pci_report(engine),
        "gdpr": generate_gdpr_report(engine)
    }
    
    # Print summary
    print_compliance_report(reports)
    
    # Save detailed reports
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    for standard, report in reports.items():
        filename = f"compliance_{standard}_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n💾 {standard.upper()} report saved to: {filename}")
    
    print(f"\n✅ Compliance reporting completed")


if __name__ == "__main__":
    main()
