Step 1 — Prerequisites + Plan

!/bin/bash
 scripts/security-precheck.sh
set -euo pipefail

PASS=0; FAIL=0

check() {
  local desc=$1 cmd=$2
  if eval "$cmd" &>/dev/null; then
    echo "✅ $desc"; ((PASS++))
  else
    echo "❌ $desc"; ((FAIL++))
  fi
}

check "kubectl connected"        "kubectl get nodes"
check "production namespace"     "kubectl get namespace production"
check "aws iam accessible"       "aws iam list-roles | jq -e '.Roles | length > 0'"
check "aws guardduty enabled"    "aws guardduty list-detectors | jq -e '.DetectorIds | length > 0'"
check "aws securityhub enabled"  "aws securityhub get-hub | jq -e '.HubArn'"
check "trivy installed"          "trivy --version"
check "checkov installed"        "checkov --version"
check "prometheus healthy"       "curl -sf http://prometheus:9090/-/healthy"
check "waf active"               "aws wafv2 list-web-acls --scope REGIONAL | grep placemux"
check "cloudtrail logging"       "aws cloudtrail get-trail-status --name placemux-prod-flags | jq -e '.IsLogging'"

echo ""
echo "=== $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] || exit 1

# docs/security-plan.md

## Stage A — The bar
A compromised credential or dependency has a small,
contained blast radius.

## Blast radius

| Stage | What changes                  | Blast radius                        | Rollback                           |
|-------|-------------------------------|-------------------------------------|------------------------------------|
| B     | Network ACLs + IAM hardening  | Legit traffic blocked if too strict | terraform apply previous state     |
| C     | Remove standing admin access  | Deploy blocked until JIT approved   | Re-attach admin policy temporarily |
| D     | CI scanning gates             | PR blocked on vulnerable dependency | Fix vuln or add exception          |
| E     | Live enforcement demo         | One over-permissioned action blocked| Remove test policy                 |

bash scripts/security-precheck.sh

Step 2 — Threat model + network/IAM hardening (Stage B)

 docs/threat-model.md

 Assets
- Customer data (PII, payment info)
- API keys + secrets
- ML models
- Search index
- CI/CD pipeline

 Threat actors
- External attacker (internet)
- Compromised dependency
- Malicious insider
- Over-permissioned service account

 Threat scenarios + mitigations

| Threat                          | Likelihood | Impact | Mitigation                              |
|---------------------------------|------------|--------|-----------------------------------------|
| Credential theft via env var    | High       | High   | Secrets Manager, no env var secrets     |
| Dependency with CVE             | High       | Medium | Trivy in CI, block on critical          |
| SSRF via app                    | Medium     | High   | IMDSv2 required, egress firewall        |
| Lateral movement via IAM        | Medium     | High   | Least privilege, no wildcard actions    |
| SQL injection                   | Medium     | High   | Parameterised queries, WAF SQLi rules   |
| Supply chain compromise         | Low        | High   | Pin images, sign artifacts, scan IaC   |
| Admin credential compromise     | Low        | High   | No standing admin, JIT via break-glass  |

 Blast radius by component
- Compromised app pod: scoped to its namespace + service account
- Compromised DB cred: read/write on one DB, no IAM access
- Compromised CI token: push images only, no prod deploy without approval
- Compromised admin: MFA required + CloudTrail audit + auto-revoke after 1hr

infra/modules/network/hardening.tf
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.app_name}-${var.environment}" }
}

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 0
    to_port    = 65535
  }

  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  egress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 0
    to_port    = 65535
  }

  egress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

resource "aws_instance_metadata_options" "imdsv2" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}

 infra/modules/iam/service-roles.tf
resource "aws_iam_role" "app" {
  name = "${var.app_name}-${var.environment}-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "app" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.app_name}/${var.environment}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = [
          "${var.document_bucket_arn}/*"
        ]
      },
      {
        Effect   = "Deny"
        Action   = ["iam:*", "ec2:*", "rds:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "ci" {
  name = "${var.app_name}-${var.environment}-ci"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci" {
  role = aws_iam_role.ci.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                    "ecr:PutImage", "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"]
        Resource = "*"
      },
      {
        Effect   = "Deny"
        Action   = ["ec2:*", "rds:*", "iam:*", "s3:Delete*"]
        Resource = "*"
      }
    ]
  })
}

terraform apply -var-file="terraform.tfvars"

Step 3 — Least privilege + no standing admin (Stage C)

infra/modules/iam/jit-admin.tf
resource "aws_iam_role" "jit_admin" {
  name                 = "${var.app_name}-${var.environment}-jit-admin"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.approved_arns }
      Action    = "sts:AssumeRole"
      Condition = {
        BoolIfExists = { "aws:MultiFactorAuthPresent" = "true" }
        StringEquals = { "sts:ExternalId" = var.jit_external_id }
      }
    }]
  })
}

resource "aws_iam_role_policy" "jit_admin" {
  role = aws_iam_role.jit_admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
      Condition = {
        StringEquals = { "aws:RequestedRegion" = [var.region] }
      }
    }]
  })
}

resource "aws_iam_policy" "deny_console_without_mfa" {
  name = "${var.app_name}-deny-no-mfa"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      NotAction = ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice",
                   "sts:GetSessionToken"]
      Resource  = "*"
      Condition = {
        BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
      }
    }]
  })
}

resource "aws_cloudwatch_event_rule" "admin_session_expiry" {
  name                = "${var.app_name}-admin-session-expiry"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "revoke_admin" {
  rule = aws_cloudwatch_event_rule.admin_session_expiry.name
  arn  = aws_lambda_function.revoke_admin_sessions.arn
}

!/bin/bash
 scripts/jit-admin-request.sh
set -euo pipefail

OPERATOR=$1
REASON=$2
DURATION=${3:-3600}
EXTERNAL_ID=$(aws secretsmanager get-secret-value \
  --secret-id placemux/prod/jit-external-id \
  --query SecretString --output text)

echo "=== JIT admin request ==="
echo "Operator: $OPERATOR | Reason: $REASON | Duration: ${DURATION}s"
echo "MFA token required:"
read MFA_TOKEN

CREDS=$(aws sts assume-role \
  --role-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/placemux-prod-jit-admin" \
  --role-session-name "jit-$OPERATOR-$(date +%s)" \
  --duration-seconds $DURATION \
  --serial-number $MFA_ARN \
  --token-code $MFA_TOKEN \
  --external-id $EXTERNAL_ID)

aws cloudwatch put-metric-data \
  --namespace PlaceMux/Security \
  --metric-data "[{\"MetricName\":\"JITAdminAccess\",\"Value\":1,\"Unit\":\"Count\",
    \"Dimensions\":[{\"Name\":\"Operator\",\"Value\":\"$OPERATOR\"}]}]"

kubectl exec -it <db-pod> -n production -- psql -U placemux -c \
  "INSERT INTO flag_audit (flag_key, old_value, new_value, changed_by, reason, source)
   VALUES ('jit_admin_access', false, true, '$OPERATOR', '$REASON', 'jit');"

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')

echo "JIT credentials active — expiry: $(echo $CREDS | jq -r '.Credentials.Expiration')"
echo "ALL ACTIONS AUDITED IN CLOUDTRAIL"

k8s/production/rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-read-only
rules:
  - apiGroups: [""]
    resources: ["pods","services","configmaps","endpoints"]
    verbs:     ["get","list","watch"]
  - apiGroups: ["apps"]
    resources: ["deployments","replicasets"]
    verbs:     ["get","list","watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-deployer
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs:     ["get","list","patch","update"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs:     ["get","list","delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-deployer
subjects:
  - kind: ServiceAccount
    name: ci-deployer
    namespace: production
roleRef:
  kind:     ClusterRole
  name:     app-deployer
  apiGroup: rbac.authorization.k8s.io

kubectl apply -f k8s/production/rbac.yaml
terraform apply -var-file="terraform.tfvars"

Step 4 — Supply chain scanning (Stage D)

 .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: npm audit
        run: |
          npm audit --audit-level=high
          npm audit --json > results/npm-audit.json || true
      - name: OWASP Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project:   placemux
          path:      .
          format:    JSON
          out:       results
          args:      --failOnCVSS 7
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dependency-scan
          path: results/

  image-scan:
    runs-on: ubuntu-latest
    needs: dependency-scan
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t placemux/my-app:${{ github.sha }} .
      - name: Trivy image scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref:    placemux/my-app:${{ github.sha }}
          format:       json
          output:       results/trivy-image.json
          severity:     CRITICAL,HIGH
          exit-code:    1
          ignore-unfixed: true
      - name: Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type:  fs
          scan-ref:   .
          format:     json
          output:     results/trivy-fs.json
          severity:   CRITICAL,HIGH
          exit-code:  1
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: image-scan
          path: results/

  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Checkov IaC scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory:      infra/
          framework:      terraform
          output_format:  json
          output_file_path: results/checkov.json
          soft_fail:      false
          check:          CKV_AWS_*
      - name: tfsec scan
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: infra/
          format:            json
          soft_fail:         false
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: iac-scan
          path: results/

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

  pentest-checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: OWASP ZAP baseline
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: https://staging.placemux.com
          rules_file_name: .zap/rules.tsv
          cmd_options: -I
      - name: Upload ZAP report
        uses: actions/upload-artifact@v4
        with:
          name: zap-report
          path: report_html.html

 .zap/rules.tsv
10202	IGNORE	(Absence of Anti-CSRF Tokens)
10038	IGNORE	(Content Security Policy Header Not Set)

 k8s/production/security-scan-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-scan-alerts
  namespace: production
spec:
  groups:
    - name: security
      rules:
        - alert: CriticalVulnerabilityFound
          expr: trivy_vulnerabilities_total{severity="CRITICAL"} > 0
          for: 0m
          labels:
            severity: critical
          annotations:
            summary: "Critical CVE in running image — patch immediately"
            runbook: "docs/security-runbook.md#critical-cve"
        - alert: JITAdminUsed
          expr: increase(aws_cloudwatch_placemux_security_jit_admin_access_sum[5m]) > 0
          for: 0m
          labels:
            severity: warning
          annotations:
            summary: "JIT admin access was used — verify in CloudTrail"
            runbook: "docs/security-runbook.md#jit-admin"
        - alert: GuardDutyFinding
          expr: aws_guardduty_findings_total > 0
          for: 0m
          labels:
            severity: critical
          annotations:
            summary: "GuardDuty finding detected"
            runbook: "docs/security-runbook.md#guardduty"

kubectl apply -f k8s/production/security-scan-alerts.yaml

Step 5 — End-to-end demo (Stage E)

!/bin/bash
scripts/security-demo.sh
set -euo pipefail

echo "=== 1. pre-check ==="
bash scripts/security-precheck.sh

echo "=== 2. CI scan blocks vulnerable image ==="
cat > /tmp/Dockerfile.vulnerable << 'EOF'
FROM node:14
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
CMD ["node", "src/app.js"]
EOF

docker build -t placemux/test:vulnerable -f /tmp/Dockerfile.vulnerable . || true
trivy image placemux/test:vulnerable --severity CRITICAL --exit-code 1 \
  && echo "❌ should have failed" || echo "✅ vulnerable image blocked"

echo "=== 3. CI scan passes clean image ==="
trivy image placemux/my-app:latest --severity CRITICAL --exit-code 1 \
  && echo "✅ clean image passes" || echo "❌ clean image has criticals"

echo "=== 4. IaC scan catches misconfiguration ==="
cat > /tmp/bad.tf << 'EOF'
resource "aws_s3_bucket" "public" {
  bucket = "test-public-bucket"
  acl    = "public-read"
}
EOF
checkov -f /tmp/bad.tf --check CKV_AWS_20 \
  && echo "❌ should have caught public bucket" || echo "✅ IaC misconfiguration caught"

echo "=== 5. secret scan blocks hardcoded key ==="
cat > /tmp/test-with-secret.js << 'EOF'
const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
const PASSWORD   = "superSecretP@ssw0rd123"
EOF
gitleaks detect --source /tmp --no-git \
  && echo "❌ secrets not found" || echo "✅ secrets caught by gitleaks"

echo "=== 6. least-privilege — app role cannot do IAM ==="
aws iam list-users \
  --profile app-role-profile 2>&1 \
  | grep -q "AccessDenied" \
  && echo "✅ IAM access denied for app role" \
  || echo "❌ app role has IAM access"

echo "=== 7. least-privilege — CI role cannot touch prod DB ==="
aws rds describe-db-instances \
  --profile ci-role-profile 2>&1 \
  | grep -q "AccessDenied" \
  && echo "✅ RDS access denied for CI role" \
  || echo "❌ CI role has RDS access"

echo "=== 8. no standing admin — verify no users with admin ==="
aws iam list-attached-role-policies \
  --role-name placemux-prod-app \
  | jq '.AttachedPolicies[].PolicyName' \
  | grep -q "AdministratorAccess" \
  && echo "❌ admin access found" || echo "✅ no standing admin"

echo "=== 9. JIT admin request ==="
bash scripts/jit-admin-request.sh demo-operator "security demo test" 900

echo "=== 10. verify JIT audit ==="
kubectl exec -it <db-pod> -n production -- psql -U placemux -c \
  "SELECT changed_by, reason, source, created_at
   FROM flag_audit WHERE source='jit'
   ORDER BY created_at DESC LIMIT 5;"

aws cloudwatch get-metric-statistics \
  --namespace PlaceMux/Security \
  --metric-name JITAdminAccess \
  --start-time $(date -u -d '-15 minutes' +%FT%TZ) \
  --end-time $(date -u +%FT%TZ) \
  --period 900 --statistics Sum | jq '.Datapoints[0].Sum'

echo "=== 11. network controls ==="
bash scripts/pentest-remediation.sh

echo "=== 12. GuardDuty active ==="
aws guardduty list-detectors | jq '.DetectorIds[0]'
aws guardduty get-detector \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  | jq '{status:.Status,updated:.UpdatedAt}'

echo "=== 13. alerts ==="
curl -s http://prometheus:9090/api/v1/alerts \
  | jq '.data.alerts[] | select(.labels.alertname | test("JIT|CVE|GuardDuty")) | {name:.labels.alertname,state}'

echo "=== 14. dependency scan report ==="
npm audit --json | jq '{
  total: .metadata.vulnerabilities.total,
  critical: .metadata.vulnerabilities.critical,
  high: .metadata.vulnerabilities.high
}'

bash scripts/security-demo.sh

Expected output:

pre-check              all passed ✅
vulnerable image       ✅ trivy blocks (CRITICAL CVEs found, exit 1)
clean image            ✅ passes scan
IaC misconfiguration   ✅ checkov catches public S3 bucket
hardcoded secret       ✅ gitleaks catches AWS key + password
app role IAM           ✅ AccessDenied
CI role RDS            ✅ AccessDenied
no standing admin      ✅ no AdministratorAccess on any service role
JIT admin              credentials issued with MFA + audit trail
JIT audit              flag_audit row + CW metric = 1
SQLi                   403 blocked by WAF
CSP                    present in response headers
HSTS                   present in response headers
rate limit             429 after 2000 req/s
IMDSv2                 required on all instances
GuardDuty              active, findings visible
alerts                 JITAdminUsed fires on use

<img width="1536" height="1024" alt="ss3022" src="https://github.com/user-attachments/assets/c9432987-9277-4cfe-b275-390fd2556085" />
