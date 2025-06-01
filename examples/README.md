# IAM Explorer Examples

This directory contains comprehensive examples and scripts demonstrating various use cases for IAM Explorer.

## 📁 Files Overview

### 🔧 Practical Scripts

- **[`security_audit.py`](security_audit.py)** - Comprehensive security audit script
  - Identifies admin users, dangerous permissions, and security violations
  - Generates detailed reports with risk assessments
  - Provides actionable recommendations

- **[`compliance_report.py`](compliance_report.py)** - Compliance reporting for various standards
  - SOX (Sarbanes-Oxley Act) compliance checks
  - PCI DSS (Payment Card Industry) requirements
  - GDPR (General Data Protection Regulation) analysis

- **[`incident_response.py`](incident_response.py)** - Incident response and forensic analysis
  - Analyzes compromised entities and blast radius
  - Identifies lateral movement paths
  - Generates incident reports with containment recommendations

- **[`automation_scripts.py`](automation_scripts.py)** - Automation and monitoring tools
  - Daily monitoring with alerting
  - Weekly security reports
  - IAM state comparison and change detection

### 📚 Reference Materials

- **[`cli_examples.sh`](cli_examples.sh)** - Comprehensive CLI command examples
  - Basic commands and workflows
  - Advanced pattern matching examples
  - Integration and automation patterns

- **[`basic_usage.py`](basic_usage.py)** - Simple programmatic usage examples

## 🚀 Quick Start

### 1. Security Audit

```bash
# Run comprehensive security audit
python examples/security_audit.py iam_graph.pkl

# Output: Detailed security findings and recommendations
```

### 2. Incident Response

```bash
# Analyze potentially compromised entity
python examples/incident_response.py suspicious-user iam_graph.pkl

# Output: Blast radius analysis and containment recommendations
```

### 3. Compliance Reporting

```bash
# Generate compliance reports for SOX, PCI DSS, and GDPR
python examples/compliance_report.py iam_graph.pkl

# Output: Compliance status and remediation guidance
```

### 4. Daily Monitoring

```bash
# Set up automated monitoring (can be run via cron)
python examples/automation_scripts.py daily-monitor

# Output: Violations detected with alerting capabilities
```

## 🎯 Use Case Examples

### Security Team Workflows

```bash
# Daily security check
./examples/cli_examples.sh | grep "Find all admin users"
iam-explorer query who-can-do '*' --format json > daily_admins.json

# Weekly audit
python examples/security_audit.py
python examples/compliance_report.py

# Incident investigation
python examples/incident_response.py compromised-account
```

### Compliance Officer Tasks

```bash
# Generate compliance reports
python examples/compliance_report.py iam_graph.pkl

# Export for external auditors
iam-explorer query who-can-do '*' --format json > admin_access_report.json
iam-explorer query who-can-do 'iam:*' --format json > iam_management_report.json
```

### DevOps Integration

```bash
# Automated monitoring in CI/CD
python examples/automation_scripts.py daily-monitor
if [ $? -eq 1 ]; then
    echo "Security violations detected - blocking deployment"
    exit 1
fi

# Compare IAM states before/after deployment
python examples/automation_scripts.py compare baseline_iam.pkl current_iam.pkl
```

## 🔍 Advanced Pattern Matching Examples

IAM Explorer now supports dynamic AWS action fetching with powerful pattern matching:

```bash
# All S3 read operations (59 specific actions)
iam-explorer query who-can-do 's3:Get*'

# All delete operations across 420+ AWS services (2000+ actions)
iam-explorer query who-can-do '*:Delete*'

# All EC2 describe operations (168 specific actions)
iam-explorer query who-can-do 'ec2:Describe*'

# All Lambda function management (70+ actions)
iam-explorer query who-can-do 'lambda:*Function*'

# Cross-service create permissions (1900+ actions)
iam-explorer query who-can-do '*:Create*'
```

## 📊 Visualization Examples

```bash
# Generate comprehensive graph
iam-explorer visualize --output complete_iam.dot

# Focus on security-critical entities
iam-explorer visualize --filter admin-user --filter security-role --output security_focus.dot

# Clean view for presentations
iam-explorer visualize --no-policies --output clean_overview.dot

# Convert to various formats
dot -Tpng complete_iam.dot -o iam_overview.png
dot -Tsvg security_focus.dot -o security_analysis.svg
```

## 🔧 Integration Patterns

### Slack Integration

```python
# In automation_scripts.py - configure Slack webhook
config = {
    "alerts": {
        "slack": {
            "enabled": True,
            "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
        }
    }
}
```

### Email Alerts

```python
# Configure SMTP for email alerts
config = {
    "alerts": {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.company.com",
            "smtp_port": 587,
            "username": "alerts@company.com",
            "password": "your-password",
            "recipients": ["security@company.com"]
        }
    }
}
```

### JSON Processing

```bash
# Extract specific information using jq
iam-explorer query who-can-do '*' --format json | jq '.[] | select(.type == "user") | .name'

# Count entities by type
iam-explorer query who-can-do 'iam:*' --format json | jq 'group_by(.type) | map({type: .[0].type, count: length})'

# Find high-risk combinations
iam-explorer query who-can-do '*:Delete*' --format json | jq '.[] | select(.name | contains("prod"))'
```

## 📈 Performance Tips

- **Cache graphs**: Build once, query many times using `--graph graph.pkl`
- **Use filters**: Focus visualizations with `--filter entity-name`
- **JSON output**: Use `--format json` for programmatic processing
- **Incremental analysis**: Compare states with automation scripts

## 🛡️ Security Best Practices

1. **Regular Audits**: Run security_audit.py weekly
2. **Continuous Monitoring**: Set up daily-monitor via cron
3. **Incident Preparedness**: Practice with incident_response.py
4. **Compliance Tracking**: Generate monthly compliance reports
5. **Change Detection**: Compare IAM states before/after changes

## 📚 Learning Path

1. **Start with CLI examples**: `./cli_examples.sh`
2. **Run basic audit**: `python security_audit.py`
3. **Explore visualizations**: Generate and view graphs
4. **Set up monitoring**: Configure automation_scripts.py
5. **Practice incident response**: Use incident_response.py

## 🤝 Contributing Examples

Have a useful IAM Explorer script or workflow? Please contribute!

1. Add your script to this directory
2. Update this README with description
3. Include usage examples and documentation
4. Submit a pull request

---

**Need help?** Check the main [README.md](../README.md) or [CONTRIBUTING.md](../CONTRIBUTING.md) for more information.
