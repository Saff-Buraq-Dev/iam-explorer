#!/usr/bin/env python3
"""
Incident Response Example for IAM Explorer

This script demonstrates how to use IAM Explorer for incident response scenarios,
such as analyzing compromised accounts and understanding blast radius.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add the src directory to the path so we can import iam_explorer
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from iam_explorer.graph_builder import GraphBuilder
from iam_explorer.query_engine import QueryEngine
from iam_explorer.visualizer import GraphVisualizer


def load_graph(graph_file: str) -> tuple:
    """Load IAM graph and return query engine and visualizer."""
    if not Path(graph_file).exists():
        print(f"❌ Graph file '{graph_file}' not found.")
        print("Run: iam-explorer fetch && iam-explorer build-graph")
        sys.exit(1)
    
    builder = GraphBuilder()
    graph = builder.load_graph(graph_file)
    engine = QueryEngine(graph)
    visualizer = GraphVisualizer(graph)
    
    return engine, visualizer


def analyze_compromised_entity(engine: QueryEngine, entity_name: str) -> dict:
    """Analyze a potentially compromised entity."""
    print(f"🚨 Analyzing potentially compromised entity: {entity_name}")
    
    # Get entity permissions
    entity_analysis = engine.what_can_entity_do(entity_name)
    
    if 'error' in entity_analysis:
        return {"error": f"Entity '{entity_name}' not found"}
    
    analysis = {
        "entity_name": entity_name,
        "entity_type": entity_analysis["entity_type"],
        "entity_arn": entity_analysis["entity_arn"],
        "analysis_timestamp": datetime.now().isoformat(),
        "blast_radius": {},
        "risk_assessment": {},
        "immediate_actions": [],
        "investigation_steps": []
    }
    
    # Analyze permissions
    effective_actions = entity_analysis.get("effective_actions", [])
    analysis["blast_radius"]["total_permissions"] = len(effective_actions)
    
    # Categorize dangerous permissions
    dangerous_patterns = {
        "admin_access": ["*"],
        "iam_management": [action for action in effective_actions if action.startswith("iam:")],
        "data_access": [action for action in effective_actions if any(service in action for service in ["s3:", "dynamodb:", "rds:"])],
        "compute_control": [action for action in effective_actions if any(service in action for service in ["ec2:", "lambda:", "ecs:"])],
        "delete_permissions": [action for action in effective_actions if "Delete" in action],
        "create_permissions": [action for action in effective_actions if "Create" in action],
        "secrets_access": [action for action in effective_actions if any(service in action for service in ["secretsmanager:", "ssm:", "kms:"])]
    }
    
    analysis["blast_radius"]["dangerous_permissions"] = dangerous_patterns
    
    # Risk assessment
    risk_score = 0
    risk_factors = []
    
    if dangerous_patterns["admin_access"]:
        risk_score += 50
        risk_factors.append("CRITICAL: Full administrative access")
        analysis["immediate_actions"].append("🔴 IMMEDIATE: Disable entity or revoke all permissions")
    
    if dangerous_patterns["iam_management"]:
        risk_score += 30
        risk_factors.append("HIGH: Can manage IAM permissions")
        analysis["immediate_actions"].append("🟡 HIGH: Review IAM changes made by this entity")
    
    if len(dangerous_patterns["delete_permissions"]) > 10:
        risk_score += 20
        risk_factors.append("MEDIUM: Extensive delete permissions")
    
    if dangerous_patterns["secrets_access"]:
        risk_score += 15
        risk_factors.append("MEDIUM: Can access secrets and encryption keys")
        analysis["investigation_steps"].append("🔍 Check if secrets were accessed")
    
    analysis["risk_assessment"] = {
        "risk_score": min(risk_score, 100),
        "risk_level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW",
        "risk_factors": risk_factors
    }
    
    # Check role assumption capabilities
    assumable_roles = entity_analysis.get("assumable_roles", [])
    if assumable_roles:
        analysis["blast_radius"]["assumable_roles"] = assumable_roles
        analysis["investigation_steps"].append("🔍 Check if any roles were assumed")
    
    # Generate investigation steps
    analysis["investigation_steps"].extend([
        "📋 Review CloudTrail logs for this entity",
        "🔍 Check recent API calls and resource access",
        "📊 Analyze access patterns for anomalies",
        "🔒 Review recent permission changes"
    ])
    
    # Generate immediate actions based on risk
    if analysis["risk_assessment"]["risk_level"] in ["CRITICAL", "HIGH"]:
        analysis["immediate_actions"].extend([
            "🚫 Disable entity immediately",
            "📞 Notify security team",
            "📋 Document incident timeline",
            "🔍 Begin forensic analysis"
        ])
    
    return analysis


def find_lateral_movement_paths(engine: QueryEngine, entity_name: str) -> dict:
    """Find potential lateral movement paths from compromised entity."""
    print(f"🔍 Analyzing lateral movement paths from: {entity_name}")
    
    entity_analysis = engine.what_can_entity_do(entity_name)
    
    if 'error' in entity_analysis:
        return {"error": f"Entity '{entity_name}' not found"}
    
    lateral_movement = {
        "source_entity": entity_name,
        "analysis_timestamp": datetime.now().isoformat(),
        "potential_paths": [],
        "high_value_targets": []
    }
    
    # Check role assumption capabilities
    assumable_roles = entity_analysis.get("assumable_roles", [])
    
    for role in assumable_roles:
        role_name = role.replace("Role: ", "")
        role_analysis = engine.what_can_entity_do(role_name)
        
        if 'error' not in role_analysis:
            role_permissions = len(role_analysis.get("effective_actions", []))
            
            path = {
                "target": role_name,
                "method": "Role Assumption",
                "target_permissions": role_permissions,
                "risk_level": "HIGH" if role_permissions > 100 else "MEDIUM" if role_permissions > 50 else "LOW"
            }
            
            # Check if target role has admin access
            if "*" in role_analysis.get("effective_actions", []):
                path["risk_level"] = "CRITICAL"
                path["notes"] = "Target role has administrative access"
                lateral_movement["high_value_targets"].append(role_name)
            
            lateral_movement["potential_paths"].append(path)
    
    # Check for IAM management capabilities that could lead to privilege escalation
    effective_actions = entity_analysis.get("effective_actions", [])
    iam_actions = [action for action in effective_actions if action.startswith("iam:")]
    
    if iam_actions:
        lateral_movement["potential_paths"].append({
            "target": "Any IAM Entity",
            "method": "IAM Permission Modification",
            "capabilities": iam_actions,
            "risk_level": "CRITICAL",
            "notes": "Can modify IAM permissions to escalate privileges"
        })
    
    return lateral_movement


def generate_incident_report(engine: QueryEngine, entity_name: str) -> dict:
    """Generate comprehensive incident response report."""
    print(f"📋 Generating incident response report for: {entity_name}")
    
    # Perform all analyses
    entity_analysis = analyze_compromised_entity(engine, entity_name)
    lateral_analysis = find_lateral_movement_paths(engine, entity_name)
    
    # Compile comprehensive report
    report = {
        "incident_id": f"IAM-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "compromised_entity": entity_name,
        "report_timestamp": datetime.now().isoformat(),
        "executive_summary": {},
        "detailed_analysis": entity_analysis,
        "lateral_movement": lateral_analysis,
        "recommendations": []
    }
    
    # Generate executive summary
    if 'error' not in entity_analysis:
        risk_level = entity_analysis["risk_assessment"]["risk_level"]
        total_permissions = entity_analysis["blast_radius"]["total_permissions"]
        
        report["executive_summary"] = {
            "risk_level": risk_level,
            "total_permissions": total_permissions,
            "immediate_containment_required": risk_level in ["CRITICAL", "HIGH"],
            "potential_lateral_movement": len(lateral_analysis.get("potential_paths", [])) > 0
        }
        
        # Generate recommendations
        if risk_level == "CRITICAL":
            report["recommendations"].extend([
                "🚨 IMMEDIATE: Disable compromised entity",
                "📞 IMMEDIATE: Activate incident response team",
                "🔒 IMMEDIATE: Review and revoke all sessions",
                "📋 URGENT: Begin forensic analysis of CloudTrail logs"
            ])
        elif risk_level == "HIGH":
            report["recommendations"].extend([
                "⚠️ URGENT: Disable or restrict entity permissions",
                "🔍 URGENT: Review recent activity in CloudTrail",
                "📋 HIGH: Document incident and notify stakeholders"
            ])
        
        report["recommendations"].extend([
            "🔄 Review and improve access controls",
            "📊 Implement enhanced monitoring",
            "🎓 Conduct security awareness training",
            "📝 Update incident response procedures"
        ])
    
    return report


def print_incident_report(report: dict):
    """Print incident report in a readable format."""
    print("\n" + "="*70)
    print("🚨 INCIDENT RESPONSE REPORT")
    print("="*70)
    
    print(f"\n📋 Incident ID: {report['incident_id']}")
    print(f"🎯 Compromised Entity: {report['compromised_entity']}")
    print(f"📅 Report Time: {report['report_timestamp']}")
    
    if 'executive_summary' in report and report['executive_summary']:
        summary = report['executive_summary']
        risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠", "LOW": "🟢"}
        
        print(f"\n📊 Executive Summary:")
        print(f"   • Risk Level: {risk_emoji.get(summary['risk_level'], '❓')} {summary['risk_level']}")
        print(f"   • Total Permissions: {summary['total_permissions']}")
        print(f"   • Immediate Containment: {'YES' if summary['immediate_containment_required'] else 'NO'}")
        print(f"   • Lateral Movement Risk: {'YES' if summary['potential_lateral_movement'] else 'NO'}")
    
    if 'detailed_analysis' in report and 'error' not in report['detailed_analysis']:
        analysis = report['detailed_analysis']
        
        print(f"\n🔍 Detailed Analysis:")
        print(f"   • Entity Type: {analysis['entity_type']}")
        print(f"   • Risk Score: {analysis['risk_assessment']['risk_score']}/100")
        
        if analysis['risk_assessment']['risk_factors']:
            print(f"   • Risk Factors:")
            for factor in analysis['risk_assessment']['risk_factors']:
                print(f"     - {factor}")
        
        dangerous = analysis['blast_radius']['dangerous_permissions']
        if dangerous['admin_access']:
            print(f"   • ⚠️ HAS ADMINISTRATIVE ACCESS")
        if dangerous['iam_management']:
            print(f"   • ⚠️ Can manage IAM ({len(dangerous['iam_management'])} permissions)")
        if dangerous['delete_permissions']:
            print(f"   • ⚠️ Has delete permissions ({len(dangerous['delete_permissions'])} actions)")
    
    if 'lateral_movement' in report and 'error' not in report['lateral_movement']:
        lateral = report['lateral_movement']
        
        if lateral['potential_paths']:
            print(f"\n🔄 Lateral Movement Analysis:")
            for path in lateral['potential_paths']:
                risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠", "LOW": "🟢"}
                emoji = risk_emoji.get(path['risk_level'], '❓')
                print(f"   • {emoji} {path['method']} → {path['target']} ({path['risk_level']})")
    
    if 'recommendations' in report:
        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"   • {rec}")
    
    print("="*70)


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python incident_response.py <entity_name> [graph_file]")
        print("Example: python incident_response.py compromised-user")
        sys.exit(1)
    
    entity_name = sys.argv[1]
    graph_file = sys.argv[2] if len(sys.argv) > 2 else "iam_graph.pkl"
    
    # Load graph
    engine, visualizer = load_graph(graph_file)
    
    # Generate incident report
    report = generate_incident_report(engine, entity_name)
    
    # Print report
    print_incident_report(report)
    
    # Save detailed report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"incident_response_{entity_name}_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n💾 Detailed report saved to: {filename}")
    
    # Generate focused visualization
    viz_filename = f"incident_graph_{entity_name}_{timestamp}.dot"
    visualizer.generate_dot(viz_filename, include_policies=True, filter_entities=[entity_name])
    print(f"📊 Incident graph saved to: {viz_filename}")
    print(f"   Convert to image: dot -Tpng {viz_filename} -o {viz_filename.replace('.dot', '.png')}")
    
    print(f"\n✅ Incident analysis completed for: {entity_name}")


if __name__ == "__main__":
    main()
