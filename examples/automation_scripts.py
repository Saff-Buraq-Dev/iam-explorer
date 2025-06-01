#!/usr/bin/env python3
"""
Automation Scripts for IAM Explorer

This module contains various automation scripts that can be used for
continuous monitoring, alerting, and integration with other systems.
"""

import json
import sys
import smtplib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Add the src directory to the path so we can import iam_explorer
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from iam_explorer.graph_builder import GraphBuilder
from iam_explorer.query_engine import QueryEngine


class IAMMonitor:
    """Continuous IAM monitoring and alerting."""
    
    def __init__(self, graph_file: str):
        """Initialize the monitor with a graph file."""
        self.graph_file = graph_file
        self.engine = self._load_engine()
    
    def _load_engine(self) -> QueryEngine:
        """Load the IAM graph and return query engine."""
        if not Path(self.graph_file).exists():
            raise FileNotFoundError(f"Graph file '{self.graph_file}' not found")
        
        builder = GraphBuilder()
        graph = builder.load_graph(self.graph_file)
        return QueryEngine(graph)
    
    def check_admin_threshold(self, max_admins: int = 5) -> dict:
        """Check if admin count exceeds threshold."""
        admins = self.engine.who_can_do('*')
        
        return {
            "check": "admin_threshold",
            "timestamp": datetime.now().isoformat(),
            "current_count": len(admins),
            "threshold": max_admins,
            "status": "VIOLATION" if len(admins) > max_admins else "OK",
            "entities": [a['name'] for a in admins] if len(admins) > max_admins else []
        }
    
    def check_iam_managers(self, max_managers: int = 3) -> dict:
        """Check if IAM manager count exceeds threshold."""
        managers = self.engine.who_can_do('iam:*')
        
        return {
            "check": "iam_managers",
            "timestamp": datetime.now().isoformat(),
            "current_count": len(managers),
            "threshold": max_managers,
            "status": "VIOLATION" if len(managers) > max_managers else "OK",
            "entities": [m['name'] for m in managers] if len(managers) > max_managers else []
        }
    
    def check_dangerous_permissions(self) -> dict:
        """Check for entities with dangerous permissions."""
        dangerous_checks = {
            "s3_delete_bucket": self.engine.who_can_do('s3:DeleteBucket'),
            "iam_create_user": self.engine.who_can_do('iam:CreateUser'),
            "all_delete": self.engine.who_can_do('*:Delete*'),
            "secrets_access": self.engine.who_can_do('secretsmanager:GetSecretValue')
        }
        
        violations = []
        for check_name, entities in dangerous_checks.items():
            if len(entities) > 2:  # Threshold of 2 for dangerous permissions
                violations.append({
                    "permission": check_name,
                    "count": len(entities),
                    "entities": [e['name'] for e in entities[:5]]  # First 5
                })
        
        return {
            "check": "dangerous_permissions",
            "timestamp": datetime.now().isoformat(),
            "status": "VIOLATION" if violations else "OK",
            "violations": violations
        }
    
    def run_all_checks(self) -> dict:
        """Run all monitoring checks."""
        results = {
            "monitoring_run": datetime.now().isoformat(),
            "checks": []
        }
        
        # Run individual checks
        checks = [
            self.check_admin_threshold(),
            self.check_iam_managers(),
            self.check_dangerous_permissions()
        ]
        
        results["checks"] = checks
        results["overall_status"] = "VIOLATION" if any(c["status"] == "VIOLATION" for c in checks) else "OK"
        
        return results


class AlertManager:
    """Manages alerts and notifications."""
    
    def __init__(self, config: dict):
        """Initialize with configuration."""
        self.config = config
    
    def send_email_alert(self, subject: str, body: str, recipients: list):
        """Send email alert."""
        if not self.config.get('email'):
            print("Email configuration not provided")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['from']
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.config['email']['smtp_server'], self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['username'], self.config['email']['password'])
            
            text = msg.as_string()
            server.sendmail(self.config['email']['from'], recipients, text)
            server.quit()
            
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False
    
    def send_slack_alert(self, message: str, webhook_url: str = None):
        """Send Slack alert."""
        webhook_url = webhook_url or self.config.get('slack', {}).get('webhook_url')
        
        if not webhook_url:
            print("Slack webhook URL not provided")
            return False
        
        try:
            payload = {"text": message}
            response = requests.post(webhook_url, json=payload)
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")
            return False
    
    def format_monitoring_alert(self, results: dict) -> str:
        """Format monitoring results into alert message."""
        if results["overall_status"] == "OK":
            return "✅ IAM monitoring check passed - no violations detected"
        
        message = "🚨 IAM Security Violations Detected!\n\n"
        
        for check in results["checks"]:
            if check["status"] == "VIOLATION":
                if check["check"] == "admin_threshold":
                    message += f"⚠️ Admin Threshold Exceeded: {check['current_count']} admins (limit: {check['threshold']})\n"
                    message += f"   Entities: {', '.join(check['entities'][:5])}\n\n"
                
                elif check["check"] == "iam_managers":
                    message += f"⚠️ IAM Manager Threshold Exceeded: {check['current_count']} managers (limit: {check['threshold']})\n"
                    message += f"   Entities: {', '.join(check['entities'][:5])}\n\n"
                
                elif check["check"] == "dangerous_permissions":
                    message += f"⚠️ Dangerous Permissions Detected:\n"
                    for violation in check["violations"]:
                        message += f"   • {violation['permission']}: {violation['count']} entities\n"
                    message += "\n"
        
        message += f"🕐 Check time: {results['monitoring_run']}\n"
        message += "Please review and take appropriate action."
        
        return message


def daily_monitoring_script():
    """Daily monitoring script that can be run via cron."""
    print("🔍 Running daily IAM monitoring...")
    
    # Configuration (in real use, load from config file)
    config = {
        "graph_file": "iam_graph.pkl",
        "thresholds": {
            "max_admins": 5,
            "max_iam_managers": 3
        },
        "alerts": {
            "email": {
                "enabled": False,  # Set to True and configure SMTP
                "recipients": ["security@company.com"]
            },
            "slack": {
                "enabled": False,  # Set to True and provide webhook
                "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
            }
        }
    }
    
    try:
        # Run monitoring checks
        monitor = IAMMonitor(config["graph_file"])
        results = monitor.run_all_checks()
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"monitoring_results_{timestamp}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"📊 Results saved to: {results_file}")
        
        # Send alerts if violations detected
        if results["overall_status"] == "VIOLATION":
            alert_manager = AlertManager(config)
            alert_message = alert_manager.format_monitoring_alert(results)
            
            print("🚨 Violations detected!")
            print(alert_message)
            
            # Send alerts (if configured)
            if config["alerts"]["email"]["enabled"]:
                alert_manager.send_email_alert(
                    "IAM Security Violations Detected",
                    alert_message,
                    config["alerts"]["email"]["recipients"]
                )
            
            if config["alerts"]["slack"]["enabled"]:
                alert_manager.send_slack_alert(
                    alert_message,
                    config["alerts"]["slack"]["webhook_url"]
                )
            
            return 1  # Exit code indicating violations
        else:
            print("✅ No violations detected")
            return 0
    
    except Exception as e:
        print(f"❌ Monitoring failed: {e}")
        return 2


def compare_iam_states(old_graph: str, new_graph: str) -> dict:
    """Compare two IAM states and identify changes."""
    print(f"🔄 Comparing IAM states: {old_graph} vs {new_graph}")
    
    # Load both graphs
    builder = GraphBuilder()
    
    old_iam_graph = builder.load_graph(old_graph)
    new_iam_graph = builder.load_graph(new_graph)
    
    old_engine = QueryEngine(old_iam_graph)
    new_engine = QueryEngine(new_iam_graph)
    
    # Compare admin users
    old_admins = set(e['name'] for e in old_engine.who_can_do('*'))
    new_admins = set(e['name'] for e in new_engine.who_can_do('*'))
    
    # Compare IAM managers
    old_iam_managers = set(e['name'] for e in old_engine.who_can_do('iam:*'))
    new_iam_managers = set(e['name'] for e in new_engine.who_can_do('iam:*'))
    
    comparison = {
        "comparison_time": datetime.now().isoformat(),
        "old_graph": old_graph,
        "new_graph": new_graph,
        "changes": {
            "admin_users": {
                "added": list(new_admins - old_admins),
                "removed": list(old_admins - new_admins),
                "unchanged": list(old_admins.intersection(new_admins))
            },
            "iam_managers": {
                "added": list(new_iam_managers - old_iam_managers),
                "removed": list(old_iam_managers - new_iam_managers),
                "unchanged": list(old_iam_managers.intersection(new_iam_managers))
            }
        },
        "summary": {
            "admin_count_change": len(new_admins) - len(old_admins),
            "iam_manager_count_change": len(new_iam_managers) - len(old_iam_managers)
        }
    }
    
    return comparison


def generate_weekly_report():
    """Generate weekly IAM security report."""
    print("📋 Generating weekly IAM security report...")
    
    graph_file = "iam_graph.pkl"
    
    try:
        monitor = IAMMonitor(graph_file)
        
        # Gather comprehensive statistics
        admin_entities = monitor.engine.who_can_do('*')
        iam_managers = monitor.engine.who_can_do('iam:*')
        s3_delete_bucket = monitor.engine.who_can_do('s3:DeleteBucket')
        secrets_access = monitor.engine.who_can_do('secretsmanager:GetSecretValue')
        delete_permissions = monitor.engine.who_can_do('*:Delete*')
        
        report = {
            "report_type": "Weekly IAM Security Report",
            "report_date": datetime.now().isoformat(),
            "statistics": {
                "total_admin_entities": len(admin_entities),
                "total_iam_managers": len(iam_managers),
                "s3_bucket_deleters": len(s3_delete_bucket),
                "secrets_accessors": len(secrets_access),
                "entities_with_delete_permissions": len(delete_permissions)
            },
            "trends": {
                "note": "Implement trend tracking by comparing with previous reports"
            },
            "recommendations": [
                "Review administrative access quarterly",
                "Implement least privilege principles",
                "Monitor for privilege escalation attempts",
                "Regular access certification process"
            ]
        }
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d')
        report_file = f"weekly_iam_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📊 Weekly report saved to: {report_file}")
        
        # Print summary
        print("\n📈 Weekly IAM Security Summary:")
        print(f"   • Admin entities: {report['statistics']['total_admin_entities']}")
        print(f"   • IAM managers: {report['statistics']['total_iam_managers']}")
        print(f"   • S3 bucket deleters: {report['statistics']['s3_bucket_deleters']}")
        print(f"   • Secrets accessors: {report['statistics']['secrets_accessors']}")
        print(f"   • Entities with delete permissions: {report['statistics']['entities_with_delete_permissions']}")
        
        return report
        
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return None


if __name__ == "__main__":
    """Main function for running automation scripts."""
    if len(sys.argv) < 2:
        print("Usage: python automation_scripts.py <command>")
        print("Commands:")
        print("  daily-monitor    - Run daily monitoring checks")
        print("  weekly-report    - Generate weekly security report")
        print("  compare <old> <new> - Compare two IAM graph states")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "daily-monitor":
        exit_code = daily_monitoring_script()
        sys.exit(exit_code)
    
    elif command == "weekly-report":
        generate_weekly_report()
    
    elif command == "compare":
        if len(sys.argv) < 4:
            print("Usage: python automation_scripts.py compare <old_graph> <new_graph>")
            sys.exit(1)
        
        old_graph = sys.argv[2]
        new_graph = sys.argv[3]
        
        comparison = compare_iam_states(old_graph, new_graph)
        
        # Print comparison results
        print("\n🔄 IAM State Comparison Results:")
        print(f"   • Admin users added: {len(comparison['changes']['admin_users']['added'])}")
        print(f"   • Admin users removed: {len(comparison['changes']['admin_users']['removed'])}")
        print(f"   • IAM managers added: {len(comparison['changes']['iam_managers']['added'])}")
        print(f"   • IAM managers removed: {len(comparison['changes']['iam_managers']['removed'])}")
        
        # Save comparison
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        comparison_file = f"iam_comparison_{timestamp}.json"
        
        with open(comparison_file, 'w') as f:
            json.dump(comparison, f, indent=2)
        
        print(f"\n💾 Comparison saved to: {comparison_file}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
