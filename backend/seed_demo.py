"""
CloudGuard-AI — Demo Data Seeder
Run once: python seed_demo.py
Populates SQLite with realistic mock scans, assets, findings, and compliance scores.
No AWS credentials needed.
"""
import asyncio
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

# ── Bootstrap app config so models import cleanly ─────────────────────────────
import os
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./cloudguard.db")
os.environ.setdefault("AI_PROVIDER", "local")
os.environ.setdefault("SECRET_KEY", "demo-secret")
os.environ.setdefault("GROQ_API_KEY", "demo")

from app.models import Scan, Asset, Finding, ComplianceResult
from app.database import engine, Base

# ── Helpers ───────────────────────────────────────────────────────────────────

def uid(): return str(uuid.uuid4())

NOW = datetime.now(timezone.utc)
def ago(minutes=0, hours=0, days=0):
    return NOW - timedelta(minutes=minutes, hours=hours, days=days)

# ── Demo Data ─────────────────────────────────────────────────────────────────

SCAN_ID = uid()

ASSETS = [
    # S3 buckets
    {"id": uid(), "type": "s3_bucket",      "aid": "arn:aws:s3:::prod-customer-data",       "name": "prod-customer-data",       "region": "us-east-1"},
    {"id": uid(), "type": "s3_bucket",      "aid": "arn:aws:s3:::dev-backups-2024",          "name": "dev-backups-2024",         "region": "us-east-1"},
    {"id": uid(), "type": "s3_bucket",      "aid": "arn:aws:s3:::ml-training-datasets",      "name": "ml-training-datasets",     "region": "us-west-2"},
    {"id": uid(), "type": "s3_bucket",      "aid": "arn:aws:s3:::static-assets-cdn",         "name": "static-assets-cdn",        "region": "us-east-1"},
    # IAM
    {"id": uid(), "type": "iam_role",       "aid": "arn:aws:iam::123456789012:role/LambdaExecRole",     "name": "LambdaExecRole",       "region": "global"},
    {"id": uid(), "type": "iam_role",       "aid": "arn:aws:iam::123456789012:role/EC2InstanceRole",    "name": "EC2InstanceRole",      "region": "global"},
    {"id": uid(), "type": "iam_policy",     "aid": "arn:aws:iam::123456789012:policy/DevFullAccess",   "name": "DevFullAccess",        "region": "global"},
    {"id": uid(), "type": "iam_user",       "aid": "arn:aws:iam::123456789012:user/ci-deploy",         "name": "ci-deploy",            "region": "global"},
    {"id": uid(), "type": "iam_user",       "aid": "arn:aws:iam::123456789012:user/john.smith",        "name": "john.smith",           "region": "global"},
    # EC2 / SGs
    {"id": uid(), "type": "security_group", "aid": "sg-0a1b2c3d4e5f",  "name": "web-tier-sg",      "region": "us-east-1"},
    {"id": uid(), "type": "security_group", "aid": "sg-9z8y7x6w5v",    "name": "bastion-sg",       "region": "us-east-1"},
    {"id": uid(), "type": "ec2_instance",   "aid": "i-0abc123def456",   "name": "prod-api-server",  "region": "us-east-1"},
    # VPC
    {"id": uid(), "type": "vpc",            "aid": "vpc-0123456789abc", "name": "prod-vpc",         "region": "us-east-1"},
    {"id": uid(), "type": "vpc",            "aid": "vpc-default-useast","name": "default",          "region": "us-east-1"},
]

# Map name → id for finding references
ASSET_MAP = {a["name"]: a for a in ASSETS}

FINDINGS_RAW = [
    # CRITICAL
    {
        "asset": "prod-customer-data", "rule_id": "S3-001", "severity": "critical",
        "title": "S3 Bucket Public Access Block Disabled",
        "description": "The S3 bucket does not have all four public access block settings enabled. This may allow public access via ACLs or bucket policies.",
        "compliance": {"CIS": "2.1.5", "NIST": "AC-3", "PCI_DSS": "1.3.2"},
        "ai_explanation": "This bucket stores customer PII and financial records but has no public access guardrails. Any bucket policy misconfiguration — even temporary — could expose all data to the internet.",
        "ai_attack": "An attacker who discovers the bucket name (trivial via certificate transparency logs or DNS enumeration) can attempt to list and download objects. If a misconfigured policy exists, full data exfiltration is possible without authentication.",
        "ai_remediation": "1. Enable all four S3 Block Public Access settings at the bucket level.\n2. Enable Block Public Access at the account level as a guardrail.\n3. Review and tighten the bucket policy using IAM Access Analyzer.\n4. Enable S3 server access logging and set up CloudWatch alerts for GetObject from public principals.\n5. Consider enabling Amazon Macie to detect sensitive data exposure."
    },
    {
        "asset": "web-tier-sg", "rule_id": "EC2-001", "severity": "critical",
        "title": "Security Group Allows Unrestricted SSH (Port 22)",
        "description": "This security group allows inbound SSH (port 22) from any IP address (0.0.0.0/0). This exposes instances to brute-force and credential-stuffing attacks from the internet.",
        "compliance": {"CIS": "5.2", "NIST": "SC-7", "PCI_DSS": "1.3.1"},
        "ai_explanation": "Port 22 open to the internet is one of the most commonly exploited vectors in cloud breaches. Automated scanners find and attack exposed SSH ports within minutes of being opened.",
        "ai_attack": "Attacker runs a credential stuffing tool (Hydra, Medusa) against port 22 using breached credential lists. If the instance uses password auth or a weak key, attacker gains shell access. From there, IAM metadata endpoint can be queried for credentials.",
        "ai_remediation": "1. Remove the 0.0.0.0/0 inbound SSH rule immediately.\n2. Restrict SSH to a specific bastion host IP or VPN CIDR.\n3. Use AWS Systems Manager Session Manager instead of SSH for all access.\n4. Enforce EC2 key-pair authentication and disable password-based SSH.\n5. Enable VPC Flow Logs to detect port scanning activity."
    },
    {
        "asset": "DevFullAccess", "rule_id": "IAM-001", "severity": "critical",
        "title": "IAM Policy Grants Wildcard Admin Permissions",
        "description": "This IAM policy contains Action:* Resource:* — full administrative access — violating least privilege.",
        "compliance": {"CIS": "1.16", "NIST": "AC-6", "PCI_DSS": "7.1.2"},
        "ai_explanation": "A policy with Action:* Resource:* is functionally equivalent to root access. Any principal with this policy can create, modify, or delete any resource in the account, including other IAM principals.",
        "ai_attack": "A compromised developer machine or leaked CI token with this policy attached allows an attacker to: create a backdoor IAM user, disable CloudTrail, exfiltrate all S3 data, and provision crypto-mining EC2 instances — all in a single API session.",
        "ai_remediation": "1. Immediately detach this policy from all principals.\n2. Use IAM Access Analyzer to identify the minimum required permissions.\n3. Replace with a scoped policy granting only specific actions on specific resources.\n4. Enforce SCP (Service Control Policies) at the Organization level to block wildcard policies.\n5. Enable AWS Config rule 'iam-no-inline-policy-check'."
    },
    {
        "asset": "bastion-sg", "rule_id": "EC2-002", "severity": "critical",
        "title": "Security Group Allows Unrestricted RDP (Port 3389)",
        "description": "This security group allows inbound RDP from 0.0.0.0/0. Exposing RDP is a leading cause of ransomware infections.",
        "compliance": {"CIS": "5.3", "NIST": "SC-7", "PCI_DSS": "1.3.1"},
        "ai_explanation": "Open RDP is the primary attack vector for ransomware gangs. Automated tools scan the entire IPv4 space for port 3389 every few hours. Weak credentials or unpatched RDP vulnerabilities lead directly to full instance compromise.",
        "ai_attack": "Attacker uses Shodan to find the exposed RDP port, then attempts BlueKeep or other RDP CVEs, or credential brute-force. Once inside, they deploy ransomware laterally across the VPC, encrypting EBS volumes and demanding payment.",
        "ai_remediation": "1. Remove 0.0.0.0/0 from RDP inbound rules immediately.\n2. Use AWS Systems Manager Fleet Manager for Windows remote access instead.\n3. If RDP is required, restrict to VPN/bastion IP range only.\n4. Apply Windows security patches (BlueKeep CVE-2019-0708 etc.).\n5. Enable GuardDuty to detect RDP brute-force attempts."
    },
    # HIGH
    {
        "asset": "dev-backups-2024", "rule_id": "S3-002", "severity": "high",
        "title": "S3 Bucket Encryption Not Enabled",
        "description": "The bucket lacks default server-side encryption. Data at rest is unencrypted.",
        "compliance": {"CIS": "2.1.1", "NIST": "SC-28", "PCI_DSS": "3.5"},
        "ai_explanation": "Backup buckets often contain database dumps, secrets, and configuration files. Without encryption, physical or logical access to S3 infrastructure exposes this data in cleartext.",
        "ai_attack": "A rogue AWS employee or a vulnerability in S3 infrastructure could allow raw data access. Additionally, if the bucket is accidentally made public, all backup data is immediately readable without any key material.",
        "ai_remediation": "1. Enable default SSE-S3 or SSE-KMS encryption on the bucket.\n2. Use SSE-KMS with a customer-managed key for backup buckets (stronger audit trail).\n3. Enable S3 Bucket Key to reduce KMS API costs.\n4. Apply an S3 bucket policy denying PutObject without encryption headers."
    },
    {
        "asset": "john.smith", "rule_id": "IAM-002", "severity": "high",
        "title": "IAM User Has No MFA Device",
        "description": "IAM user john.smith has no MFA device configured. Console login is protected by password only.",
        "compliance": {"CIS": "1.5", "NIST": "IA-2", "PCI_DSS": "8.3.1"},
        "ai_explanation": "Without MFA, a single stolen or phished password gives full console access. Phishing campaigns targeting AWS users are extremely common and highly effective.",
        "ai_attack": "Attacker phishes john.smith's credentials via a fake AWS login page. Without MFA, they log straight into the AWS console, review billing to understand account size, then launch crypto-mining instances or exfiltrate S3 data.",
        "ai_remediation": "1. Require MFA immediately via IAM policy: deny console access without MFA.\n2. Enroll john.smith in a virtual MFA device (Google Authenticator, Authy) or hardware key (YubiKey).\n3. Apply an IAM policy that enforces MFA across all users.\n4. Consider moving to SSO (AWS Identity Center) with MFA enforced at the IdP level."
    },
    {
        "asset": "ci-deploy", "rule_id": "IAM-003", "severity": "high",
        "title": "IAM User Access Key Not Rotated (>90 days)",
        "description": "Access key for ci-deploy has not been rotated in over 90 days, increasing compromise risk.",
        "compliance": {"CIS": "1.14", "NIST": "IA-5", "PCI_DSS": "8.3.9"},
        "ai_explanation": "Long-lived credentials are a primary target for attackers scanning code repositories, CI logs, and environment variables. The longer a key exists, the more likely it has been inadvertently exposed.",
        "ai_attack": "Developer accidentally commits .env file containing the key to a public GitHub repo. Automated scanners (like truffleHog or GitGuardian bots operated by attackers) find the key within minutes and begin API calls to exfiltrate data.",
        "ai_remediation": "1. Rotate the access key immediately — create new, update CI/CD secrets, delete old.\n2. Use IAM Roles for CI/CD instead of long-lived access keys (GitHub Actions OIDC, etc.).\n3. Set up AWS Config rule 'access-keys-rotated' to alert on keys older than 90 days.\n4. Enable CloudTrail and alert on API calls from the key outside normal hours/regions."
    },
    # MEDIUM
    {
        "asset": "ml-training-datasets", "rule_id": "S3-003", "severity": "medium",
        "title": "S3 Bucket Versioning Disabled",
        "description": "Versioning is disabled. Accidental deletions or overwrites cannot be recovered.",
        "compliance": {"CIS": "2.1.3", "NIST": "CP-9", "PCI_DSS": "10.5.1"},
        "ai_explanation": "Without versioning, a single rm -rf equivalent API call or ransomware that overwrites objects destroys data permanently. ML training datasets are expensive to recreate.",
        "ai_attack": "Attacker with write access (or a confused-deputy attack via a Lambda) deletes or overwrites all training data. Without versioning, recovery is impossible. Alternatively, ransomware encrypts objects and deletes originals.",
        "ai_remediation": "1. Enable S3 versioning on the bucket.\n2. Configure S3 Object Lock for immutability on critical datasets.\n3. Set up lifecycle rules to expire old versions after 30-90 days to control costs.\n4. Enable MFA Delete to prevent accidental or malicious version deletion."
    },
    {
        "asset": "prod-vpc", "rule_id": "VPC-001", "severity": "medium",
        "title": "VPC Flow Logs Not Enabled",
        "description": "VPC Flow Logs are not enabled. Network traffic is unaudited.",
        "compliance": {"CIS": "3.9", "NIST": "AU-12", "PCI_DSS": "10.8"},
        "ai_explanation": "Without flow logs, there is no visibility into what traffic enters and exits the VPC. Security incidents cannot be investigated and lateral movement goes undetected.",
        "ai_attack": "Attacker establishes C2 (command and control) from a compromised EC2 instance. Without flow logs, the outbound beaconing traffic is invisible. Incident response teams have no forensic data to determine scope of breach.",
        "ai_remediation": "1. Enable VPC Flow Logs for the prod-vpc, sending to CloudWatch Logs or S3.\n2. Set retention to at least 90 days (PCI-DSS requires 1 year).\n3. Create CloudWatch Metric Filters to alert on unusual traffic patterns.\n4. Consider enabling GuardDuty which uses flow log data for threat detection."
    },
    {
        "asset": "prod-customer-data", "rule_id": "S3-004", "severity": "medium",
        "title": "S3 Bucket Access Logging Not Enabled",
        "description": "S3 server access logging is disabled. No audit trail for data access.",
        "compliance": {"CIS": "2.1.2", "NIST": "AU-2", "PCI_DSS": "10.2"},
        "ai_explanation": "For a bucket storing customer data, access logging is mandatory for compliance. Without it, you cannot prove who accessed what data, when — a critical requirement for GDPR and PCI-DSS breach investigations.",
        "ai_attack": "After a breach, forensic investigators cannot determine which files were accessed, by whom, or when — making breach notification scope impossible to determine, leading to over-notification and regulatory penalties.",
        "ai_remediation": "1. Enable S3 server access logging, targeting a dedicated audit log bucket.\n2. Ensure the log bucket itself has versioning and no public access.\n3. Set up S3 Event Notifications for sensitive operations (DeleteObject, GetObject).\n4. Integrate logs with a SIEM for real-time alerting."
    },
    # LOW
    {
        "asset": "default", "rule_id": "VPC-002", "severity": "low",
        "title": "Default VPC Detected",
        "description": "The default VPC exists in this region. Default VPCs have permissive defaults and should be removed.",
        "compliance": {"CIS": "5.5", "NIST": "SC-7", "PCI_DSS": "1.2.1"},
        "ai_explanation": "Default VPCs are created by AWS with permissive default security groups that allow all inbound traffic between instances. Resources accidentally launched into the default VPC inherit these rules.",
        "ai_attack": "A developer accidentally launches a test EC2 instance into the default VPC instead of prod-vpc. The permissive default security group allows all traffic from other instances in the VPC, potentially exposing internal services.",
        "ai_remediation": "1. Delete the default VPC from all regions where it is not intentionally used.\n2. Use AWS Config rule 'vpc-default-security-group-closed' to monitor.\n3. Apply an SCP to prevent use of the default VPC in production accounts.\n4. Audit all resources to ensure none are deployed in the default VPC."
    },
    {
        "asset": "static-assets-cdn", "rule_id": "S3-003", "severity": "low",
        "title": "S3 Bucket Versioning Disabled",
        "description": "Versioning disabled on CDN assets bucket.",
        "compliance": {"CIS": "2.1.3", "NIST": "CP-9", "PCI_DSS": "10.5.1"},
        "ai_explanation": "While CDN assets are lower risk than customer data, versioning allows rollback if an attacker modifies JS/CSS files to inject malicious scripts (supply chain attack).",
        "ai_attack": "Attacker gains write access and modifies a JavaScript file to inject a keylogger or crypto-miner. Without versioning, the clean version cannot be quickly restored.",
        "ai_remediation": "1. Enable S3 versioning.\n2. Set up CloudFront cache invalidation alerts for unexpected changes.\n3. Consider S3 Object Lock with a 24-hour retention for CDN assets.\n4. Enable S3 event notifications for PutObject on this bucket."
    },
]

# ── Compliance data ───────────────────────────────────────────────────────────

COMPLIANCE = [
    {
        "framework": "CIS",
        "score": 62.5,
        "passed": 10,
        "failed": 6,
        "details": {
            "2.1.5": {"status": "FAIL", "rule_id": "S3-001", "title": "S3 Public Access Block", "severity": "critical"},
            "2.1.1": {"status": "FAIL", "rule_id": "S3-002", "title": "S3 Encryption", "severity": "high"},
            "2.1.3": {"status": "FAIL", "rule_id": "S3-003", "title": "S3 Versioning", "severity": "medium"},
            "2.1.2": {"status": "FAIL", "rule_id": "S3-004", "title": "S3 Logging", "severity": "medium"},
            "5.2":   {"status": "FAIL", "rule_id": "EC2-001", "title": "Unrestricted SSH", "severity": "critical"},
            "5.3":   {"status": "FAIL", "rule_id": "EC2-002", "title": "Unrestricted RDP", "severity": "critical"},
            "1.16":  {"status": "FAIL", "rule_id": "IAM-001", "title": "Wildcard IAM", "severity": "critical"},
            "1.5":   {"status": "PASS"},
            "1.14":  {"status": "PASS"},
            "3.9":   {"status": "FAIL", "rule_id": "VPC-001", "title": "VPC Flow Logs", "severity": "medium"},
            "5.5":   {"status": "PASS"},
            "5.4":   {"status": "PASS"},
            "1.4":   {"status": "PASS"},
            "3.1":   {"status": "PASS"},
            "2.3":   {"status": "PASS"},
            "4.1":   {"status": "PASS"},
        }
    },
    {
        "framework": "NIST",
        "score": 70.0,
        "passed": 14,
        "failed": 6,
        "details": {
            "AC-3":  {"status": "FAIL", "rule_id": "S3-001", "title": "Access Control", "severity": "critical"},
            "SC-28": {"status": "FAIL", "rule_id": "S3-002", "title": "Encryption at Rest", "severity": "high"},
            "CP-9":  {"status": "FAIL", "rule_id": "S3-003", "title": "System Backup", "severity": "medium"},
            "AU-2":  {"status": "FAIL", "rule_id": "S3-004", "title": "Audit Events", "severity": "medium"},
            "SC-7":  {"status": "FAIL", "rule_id": "EC2-001", "title": "Boundary Protection", "severity": "critical"},
            "AC-6":  {"status": "FAIL", "rule_id": "IAM-001", "title": "Least Privilege", "severity": "critical"},
            "IA-2":  {"status": "PASS"},
            "IA-5":  {"status": "PASS"},
            "AU-12": {"status": "PASS"},
            "AC-2":  {"status": "PASS"},
            "SI-2":  {"status": "PASS"},
            "IR-4":  {"status": "PASS"},
        }
    },
    {
        "framework": "PCI-DSS",
        "score": 55.0,
        "passed": 11,
        "failed": 9,
        "details": {
            "1.3.2": {"status": "FAIL", "rule_id": "S3-001", "title": "Restrict Inbound Traffic", "severity": "critical"},
            "3.5":   {"status": "FAIL", "rule_id": "S3-002", "title": "Protect Stored Data", "severity": "high"},
            "10.5.1":{"status": "FAIL", "rule_id": "S3-003", "title": "Protect Audit Logs", "severity": "medium"},
            "10.2":  {"status": "FAIL", "rule_id": "S3-004", "title": "Implement Audit Logs", "severity": "medium"},
            "1.3.1": {"status": "FAIL", "rule_id": "EC2-001", "title": "Restrict Inbound Internet", "severity": "critical"},
            "7.1.2": {"status": "FAIL", "rule_id": "IAM-001", "title": "Least Privilege Access", "severity": "critical"},
            "8.3.1": {"status": "FAIL", "rule_id": "IAM-002", "title": "MFA for Console Access", "severity": "high"},
            "8.3.9": {"status": "FAIL", "rule_id": "IAM-003", "title": "Key Rotation", "severity": "high"},
            "10.8":  {"status": "FAIL", "rule_id": "VPC-001", "title": "Security Control Monitoring", "severity": "medium"},
            "1.2.1": {"status": "PASS"},
            "6.3.3": {"status": "PASS"},
            "8.2.1": {"status": "PASS"},
        }
    },
]

# ── Seed function ─────────────────────────────────────────────────────────────

async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with AsyncSessionLocal() as db:
        # Scan
        scan = Scan(
            id=SCAN_ID,
            status="completed",
            account_id="123456789012",
            region="us-east-1",
            services=["s3", "iam", "ec2", "vpc"],
            triggered_by="demo-seeder",
            started_at=ago(hours=1),
            completed_at=ago(minutes=45),
            total_findings=len(FINDINGS_RAW),
            critical_count=sum(1 for f in FINDINGS_RAW if f["severity"] == "critical"),
            high_count=sum(1 for f in FINDINGS_RAW if f["severity"] == "high"),
            medium_count=sum(1 for f in FINDINGS_RAW if f["severity"] == "medium"),
            low_count=sum(1 for f in FINDINGS_RAW if f["severity"] == "low"),
        )
        db.add(scan)
        await db.flush()

        # Assets
        asset_db_map = {}
        for a in ASSETS:
            asset = Asset(
                id=a["id"],
                scan_id=SCAN_ID,
                asset_type=a["type"],
                asset_id=a["aid"],
                asset_name=a["name"],
                region=a["region"],
                raw_config={},
            )
            db.add(asset)
            asset_db_map[a["name"]] = asset
        await db.flush()

        # Findings
        for f in FINDINGS_RAW:
            asset = asset_db_map[f["asset"]]
            finding = Finding(
                id=uid(),
                scan_id=SCAN_ID,
                asset_id=asset.id,
                rule_id=f["rule_id"],
                title=f["title"],
                description=f["description"],
                severity=f["severity"],
                status="open",
                compliance_mappings=f["compliance"],
                ai_explanation=f["ai_explanation"],
                ai_attack_scenario=f["ai_attack"],
                ai_remediation=f["ai_remediation"],
            )
            db.add(finding)

        # Compliance
        for c in COMPLIANCE:
            cr = ComplianceResult(
                id=uid(),
                scan_id=SCAN_ID,
                framework=c["framework"],
                score=c["score"],
                passed_controls=c["passed"],
                failed_controls=c["failed"],
                control_details=c["details"],
            )
            db.add(cr)

        await db.commit()
        print(f"""
✅  Demo data seeded successfully!

    Scan ID : {SCAN_ID}
    Assets  : {len(ASSETS)}
    Findings: {len(FINDINGS_RAW)} ({sum(1 for f in FINDINGS_RAW if f['severity']=='critical')}C / {sum(1 for f in FINDINGS_RAW if f['severity']=='high')}H / {sum(1 for f in FINDINGS_RAW if f['severity']=='medium')}M / {sum(1 for f in FINDINGS_RAW if f['severity']=='low')}L)
    Compliance: CIS 62.5% · NIST 70% · PCI-DSS 55%

→  Open http://localhost:5173 to see the dashboard
→  Or hit http://localhost:8000/api/v1/dashboard/stats
""")

if __name__ == "__main__":
    asyncio.run(seed())
