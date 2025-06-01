#!/bin/bash
# IAM Explorer CLI Examples
# This script demonstrates various CLI commands and use cases

echo "🚀 IAM Explorer CLI Examples"
echo "================================"

# Check if iam-explorer is installed
if ! command -v iam-explorer &> /dev/null; then
    echo "❌ iam-explorer not found. Please install it first:"
    echo "   pip install -e ."
    exit 1
fi

echo ""
echo "📋 Basic Commands"
echo "----------------"

echo "# 1. Get help"
echo "iam-explorer --help"
echo ""

echo "# 2. Fetch IAM data from AWS"
echo "iam-explorer fetch --output iam_data.json"
echo "iam-explorer fetch --profile production --region us-west-2 --output prod_iam.json"
echo "iam-explorer fetch --include-aws-managed --output complete_iam.json"
echo ""

echo "# 3. Build graph from data"
echo "iam-explorer build-graph --input iam_data.json --output iam_graph.pkl"
echo ""

echo ""
echo "🔍 Security Analysis Queries"
echo "----------------------------"

echo "# Find all admin users"
echo "iam-explorer query who-can-do '*'"
echo ""

echo "# Find who can manage IAM"
echo "iam-explorer query who-can-do 'iam:*'"
echo ""

echo "# Find dangerous delete permissions"
echo "iam-explorer query who-can-do '*:Delete*'"
echo ""

echo "# Find S3 bucket deletion permissions"
echo "iam-explorer query who-can-do 's3:DeleteBucket'"
echo ""

echo "# Find who can access secrets"
echo "iam-explorer query who-can-do 'secretsmanager:GetSecretValue'"
echo ""

echo "# Find who can decrypt with KMS"
echo "iam-explorer query who-can-do 'kms:Decrypt'"
echo ""

echo ""
echo "🎯 Advanced Pattern Matching"
echo "----------------------------"

echo "# All S3 read operations (Get actions)"
echo "iam-explorer query who-can-do 's3:Get*'"
echo ""

echo "# All S3 write operations (Put actions)"
echo "iam-explorer query who-can-do 's3:Put*'"
echo ""

echo "# All EC2 describe operations"
echo "iam-explorer query who-can-do 'ec2:Describe*'"
echo ""

echo "# All Lambda function operations"
echo "iam-explorer query who-can-do 'lambda:*Function*'"
echo ""

echo "# All create operations across services"
echo "iam-explorer query who-can-do '*:Create*'"
echo ""

echo "# All list operations across services"
echo "iam-explorer query who-can-do '*:List*'"
echo ""

echo ""
echo "👤 Entity Analysis"
echo "-----------------"

echo "# Analyze what a user can do"
echo "iam-explorer query what-can-do alice"
echo "iam-explorer query what-can-do suspicious-user"
echo ""

echo "# Analyze what a role can do"
echo "iam-explorer query what-can-do lambda-execution-role"
echo "iam-explorer query what-can-do ec2-instance-role"
echo ""

echo "# Get JSON output for automation"
echo "iam-explorer query what-can-do admin-user --format json"
echo ""

echo ""
echo "📊 Visualization Commands"
echo "------------------------"

echo "# Generate basic graph"
echo "iam-explorer visualize --output iam_graph.dot"
echo ""

echo "# Generate PNG directly"
echo "iam-explorer visualize --format png --output iam_graph.png"
echo ""

echo "# Focus on specific entities"
echo "iam-explorer visualize --filter alice --filter bob --output user_focus.dot"
echo ""

echo "# Clean view without policies"
echo "iam-explorer visualize --no-policies --output clean_view.dot"
echo ""

echo "# Convert DOT to images (requires Graphviz)"
echo "dot -Tpng iam_graph.dot -o iam_graph.png"
echo "dot -Tsvg iam_graph.dot -o iam_graph.svg"
echo "dot -Tpdf iam_graph.dot -o iam_graph.pdf"
echo ""

echo ""
echo "🔒 Compliance and Auditing"
echo "-------------------------"

echo "# Export admin users for compliance"
echo "iam-explorer query who-can-do '*' --format json > admin_users.json"
echo ""

echo "# Export IAM managers for security review"
echo "iam-explorer query who-can-do 'iam:*' --format json > iam_managers.json"
echo ""

echo "# Find cross-service dangerous permissions"
echo "iam-explorer query who-can-do '*:Delete*' --format json > delete_permissions.json"
echo ""

echo "# Audit specific high-risk permissions"
echo "iam-explorer query who-can-do 's3:DeleteBucket' --format json > s3_delete_audit.json"
echo "iam-explorer query who-can-do 'iam:CreateUser' --format json > user_creation_audit.json"
echo "iam-explorer query who-can-do 'iam:AttachUserPolicy' --format json > policy_attachment_audit.json"
echo ""

echo ""
echo "🚨 Incident Response"
echo "-------------------"

echo "# Quick analysis of suspicious user"
echo "iam-explorer query what-can-do compromised-user --format json > incident_analysis.json"
echo ""

echo "# Find who has similar permissions to compromised account"
echo "iam-explorer query who-can-do 's3:*' | grep -v compromised-user"
echo ""

echo "# Generate focused incident graph"
echo "iam-explorer visualize --filter compromised-user --output incident_graph.dot"
echo ""

echo ""
echo "⚡ Performance Tips"
echo "-----------------"

echo "# For large environments, use filters"
echo "iam-explorer visualize --filter critical-role --no-policies --output focused.dot"
echo ""

echo "# Use JSON output for programmatic processing"
echo "iam-explorer query who-can-do '*' --format json | jq '.[] | select(.type == \"user\")'"
echo ""

echo "# Cache graphs for repeated analysis"
echo "# Build once: iam-explorer build-graph --input data.json --output graph.pkl"
echo "# Use many times: iam-explorer query who-can-do 'action' --graph graph.pkl"
echo ""

echo ""
echo "🔧 Integration Examples"
echo "----------------------"

echo "# Daily security check script"
echo "#!/bin/bash"
echo "ADMIN_COUNT=\$(iam-explorer query who-can-do '*' --format json | jq '. | length')"
echo "if [ \"\$ADMIN_COUNT\" -gt 5 ]; then"
echo "    echo \"WARNING: \$ADMIN_COUNT admin users detected\""
echo "    # Send alert"
echo "fi"
echo ""

echo "# Find new admin users (compare with baseline)"
echo "iam-explorer query who-can-do '*' --format json > current_admins.json"
echo "# Compare with previous baseline_admins.json"
echo ""

echo "# Generate weekly compliance report"
echo "iam-explorer query who-can-do 'iam:*' --format json > weekly_iam_managers.json"
echo "iam-explorer query who-can-do '*:Delete*' --format json > weekly_delete_permissions.json"
echo ""

echo ""
echo "📚 Learning Examples"
echo "-------------------"

echo "# Understand AWS service actions"
echo "iam-explorer query who-can-do 's3:*' | head -20  # See all S3 permissions"
echo "iam-explorer query who-can-do 'lambda:*' | head -20  # See all Lambda permissions"
echo ""

echo "# Explore role relationships"
echo "iam-explorer query what-can-do cross-account-role"
echo "iam-explorer visualize --filter cross-account-role --output role_analysis.dot"
echo ""

echo "# Understand permission inheritance"
echo "iam-explorer query what-can-do group-member-user"
echo "iam-explorer visualize --filter group-member-user --output inheritance.dot"
echo ""

echo ""
echo "✅ Example Complete!"
echo "==================="
echo ""
echo "💡 Tips:"
echo "• Use --help with any command for detailed options"
echo "• Start with basic queries and build up to complex analysis"
echo "• Save graphs (.pkl files) for repeated analysis"
echo "• Use JSON output for automation and integration"
echo "• Visualizations help understand complex relationships"
echo ""
echo "📖 For more examples, see the examples/ directory"
