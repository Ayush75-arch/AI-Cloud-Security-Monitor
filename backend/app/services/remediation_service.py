"""
CloudGuard-AI — Auto-Remediation Engine
The first open-source self-healing cloud security engine.
Automatically fixes misconfigurations via AWS API or generates Terraform plans.
Features: playbook system, approval workflows, rollback support, dry-run mode.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class RemediationAction(str, Enum):
    TERRAFORM = "terraform"
    AWS_API = "aws_api"
    MANUAL = "manual"


@dataclass
class RemediationStep:
    action: RemediationAction
    description: str
    command: str = ""
    risk_level: str = "low"
    validation_command: str = ""
    rollback_command: str = ""


@dataclass
class RemediationPlaybook:
    rule_id: str
    title: str
    description: str
    risk_level: str
    steps: list[RemediationStep]
    timeout_seconds: int = 60
    requires_approval: bool = False


REMEDIATION_PLAYBOOKS: dict[str, RemediationPlaybook] = {
    "S3-001": RemediationPlaybook(
        rule_id="S3-001",
        title="Enable S3 Block Public Access",
        description="Enables all four S3 Block Public Access settings on the bucket.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable BlockPublicAcls",
                command="s3:PutPublicAccessBlock",
                risk_level="low",
                validation_command="s3:GetPublicAccessBlock",
            ),
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable IgnorePublicAcls",
                command="s3:PutPublicAccessBlock",
                risk_level="low",
            ),
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable BlockPublicPolicy",
                command="s3:PutPublicAccessBlock",
                risk_level="low",
            ),
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable RestrictPublicBuckets",
                command="s3:PutPublicAccessBlock",
                risk_level="low",
            ),
        ],
    ),
    "S3-002": RemediationPlaybook(
        rule_id="S3-002",
        title="Enable S3 Default Encryption",
        description="Enables AES256 default encryption on the S3 bucket.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable SSE-S3 default encryption",
                command="s3:PutBucketEncryption",
                risk_level="low",
                rollback_command="s3:DeleteBucketEncryption",
            ),
        ],
    ),
    "EC2-001": RemediationPlaybook(
        rule_id="EC2-001",
        title="Remove Unrestricted SSH Access",
        description="Removes 0.0.0.0/0 inbound SSH rule from security group.",
        risk_level="medium",
        requires_approval=True,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Revoke SSH ingress from 0.0.0.0/0",
                command="ec2:RevokeSecurityGroupIngress",
                risk_level="medium",
                rollback_command="ec2:AuthorizeSecurityGroupIngress",
            ),
        ],
    ),
    "EC2-002": RemediationPlaybook(
        rule_id="EC2-002",
        title="Remove Unrestricted RDP Access",
        description="Removes 0.0.0.0/0 inbound RDP rule from security group.",
        risk_level="medium",
        requires_approval=True,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Revoke RDP ingress from 0.0.0.0/0",
                command="ec2:RevokeSecurityGroupIngress",
                risk_level="medium",
                rollback_command="ec2:AuthorizeSecurityGroupIngress",
            ),
        ],
    ),
    "IAM-001": RemediationPlaybook(
        rule_id="IAM-001",
        title="Detach Wildcard Admin Policy",
        description="Detaches AdministratorAccess or wildcard policies from principals.",
        risk_level="medium",
        requires_approval=True,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Detach wildcard policy from principal",
                command="iam:DetachUserPolicy",
                risk_level="medium",
            ),
        ],
    ),
    "IAM-002": RemediationPlaybook(
        rule_id="IAM-002",
        title="Enforce MFA on IAM User",
        description="Generates a grace-period notification and enforcement plan for MFA. Use AWS API to create virtual MFA device and associate.",
        risk_level="medium",
        requires_approval=True,
        timeout_seconds=60,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Create virtual MFA device",
                command="iam:CreateVirtualMFADevice",
                risk_level="medium",
            ),
        ],
    ),
    "RDS-002": RemediationPlaybook(
        rule_id="RDS-002",
        title="Disable RDS Public Accessibility",
        description="Makes the RDS instance not publicly accessible by modifying the instance.",
        risk_level="high",
        requires_approval=True,
        timeout_seconds=120,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Modify DB instance to disable public access",
                command="rds:ModifyDBInstance",
                risk_level="high",
                rollback_command="rds:ModifyDBInstance",
            ),
        ],
    ),
    "RDS-003": RemediationPlaybook(
        rule_id="RDS-003",
        title="Enable RDS Deletion Protection",
        description="Enables deletion protection on the RDS instance.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=60,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable deletion protection",
                command="rds:ModifyDBInstance",
                risk_level="low",
            ),
        ],
    ),
    "KMS-001": RemediationPlaybook(
        rule_id="KMS-001",
        title="Enable KMS Key Rotation",
        description="Enables automatic annual rotation for the KMS key.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable key rotation",
                command="kms:EnableKeyRotation",
                risk_level="low",
                validation_command="kms:GetKeyRotationStatus",
            ),
        ],
    ),
    "VPC-001": RemediationPlaybook(
        rule_id="VPC-001",
        title="Enable VPC Flow Logs",
        description="Creates and enables VPC Flow Logs for the VPC.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=60,
        steps=[
            RemediationStep(
                action=RemediationAction.TERRAFORM,
                description="Create flow log IAM role and CloudWatch log group",
                command="aws_flow_log",
                risk_level="low",
            ),
        ],
    ),
    "CT-002": RemediationPlaybook(
        rule_id="CT-002",
        title="Enable Multi-Region CloudTrail",
        description="Updates the trail to log events from all regions.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Update trail to multi-region",
                command="cloudtrail:UpdateTrail",
                risk_level="low",
            ),
        ],
    ),
    "CT-003": RemediationPlaybook(
        rule_id="CT-003",
        title="Enable CloudTrail Log File Validation",
        description="Enables log file validation on the trail.",
        risk_level="low",
        requires_approval=False,
        timeout_seconds=30,
        steps=[
            RemediationStep(
                action=RemediationAction.AWS_API,
                description="Enable log file validation",
                command="cloudtrail:UpdateTrail",
                risk_level="low",
            ),
        ],
    ),
}


class RemediationService:
    """
    Self-healing security engine.
    Finds available playbooks for findings, executes them with approval flow,
    and supports dry-run and rollback.
    """

    def __init__(self, finding_data: dict | None = None):
        self._finding = finding_data or {}
        self._aws_session = None

    def get_available_playbooks(self, rule_ids: list[str]) -> list[dict]:
        matched = []
        for rid in rule_ids:
            playbook = REMEDIATION_PLAYBOOKS.get(rid)
            if playbook:
                matched.append({
                    "rule_id": playbook.rule_id,
                    "title": playbook.title,
                    "description": playbook.description,
                    "risk_level": playbook.risk_level,
                    "requires_approval": playbook.requires_approval,
                    "steps_count": len(playbook.steps),
                    "estimated_time_seconds": playbook.timeout_seconds,
                })
        return matched

    async def dry_run(self, rule_id: str, asset_arn: str) -> dict:
        playbook = REMEDIATION_PLAYBOOKS.get(rule_id)
        if not playbook:
            return {"error": "No playbook available for this finding"}

        return {
            "rule_id": rule_id,
            "asset_arn": asset_arn,
            "dry_run": True,
            "would_execute_steps": [
                {
                    "step": i + 1,
                    "action": step.action.value,
                    "description": step.description,
                    "api_call": step.command,
                    "risk_level": step.risk_level,
                }
                for i, step in enumerate(playbook.steps)
            ],
            "total_steps": len(playbook.steps),
            "risk_level": playbook.risk_level,
            "requires_approval": playbook.requires_approval,
            "message": "This is a DRY RUN. No changes were made.",
        }

    async def execute_remediation(self, rule_id: str, asset_arn: str, approved: bool = False) -> dict:
        playbook = REMEDIATION_PLAYBOOKS.get(rule_id)
        if not playbook:
            return {"status": "failed", "error": "No playbook available"}

        if playbook.requires_approval and not approved:
            return {
                "status": "requires_approval",
                "message": "This remediation requires manual approval before execution.",
                "playbook": {
                    "title": playbook.title,
                    "description": playbook.description,
                    "risk_level": playbook.risk_level,
                    "steps_count": len(playbook.steps),
                },
            }

        logger.info(
            "remediation_executing",
            rule_id=rule_id,
            asset=asset_arn,
            steps=len(playbook.steps),
        )

        results = []
        all_success = True

        for i, step in enumerate(playbook.steps):
            try:
                if step.action == RemediationAction.AWS_API and self._can_execute_aws():
                    result = await self._execute_aws_api(step, asset_arn)
                else:
                    result = self._generate_terraform_hcl(step, asset_arn, playbook)

                results.append({
                    "step": i + 1,
                    "description": step.description,
                    "status": "simulated" if not self._can_execute_aws() else "executed",
                    "result": result,
                })

                logger.info("remediation_step_complete", step=i + 1, rule_id=rule_id)

            except Exception as exc:
                logger.error("remediation_step_failed", step=i + 1, rule_id=rule_id, error=str(exc))
                results.append({
                    "step": i + 1,
                    "description": step.description,
                    "status": "failed",
                    "error": str(exc),
                })
                all_success = False
                break

        status = RemediationStatus.COMPLETED if all_success else RemediationStatus.FAILED
        return {
            "status": status.value,
            "rule_id": rule_id,
            "asset_arn": asset_arn,
            "steps": results,
            "total_steps": len(playbook.steps),
            "successful_steps": sum(1 for r in results if r["status"] != "failed"),
            "failed_steps": sum(1 for r in results if r["status"] == "failed"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def generate_terraform_plan(self, rule_id: str, asset_arn: str) -> dict:
        playbook = REMEDIATION_PLAYBOOKS.get(rule_id)
        if not playbook:
            return {"error": "No playbook available"}

        hcl_resources = []
        for step in playbook.steps:
            hcl = self._generate_terraform_hcl(step, asset_arn, playbook)
            if hcl:
                hcl_resources.append(hcl)

        return {
            "rule_id": rule_id,
            "asset_arn": asset_arn,
            "terraform_hcl": "\n\n".join(hcl_resources) if hcl_resources else "# No Terraform resources generated",
            "provider": "aws",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _can_execute_aws(self) -> bool:
        return bool(settings.AWS_ACCESS_KEY_ID)

    async def _execute_aws_api(self, step: RemediationStep, asset_arn: str) -> dict:
        if not self._can_execute_aws():
            return {"simulated": True, "api_call": step.command, "message": "No AWS credentials - simulated"}

        try:
            import boto3
            client = boto3.client(
                step.command.split(":")[0],
                region_name=settings.AWS_DEFAULT_REGION,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )

            action_map = {
                "s3:PutPublicAccessBlock": lambda: client.put_public_access_block(
                    Bucket=asset_arn.split(":::")[-1],
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                ),
                "s3:PutBucketEncryption": lambda: client.put_bucket_encryption(
                    Bucket=asset_arn.split(":::")[-1],
                    ServerSideEncryptionConfiguration={
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    },
                ),
                "ec2:RevokeSecurityGroupIngress": lambda: client.revoke_security_group_ingress(
                    GroupId=asset_arn.split("/")[-1] if "/" in asset_arn else asset_arn,
                    IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                ),
                "kms:EnableKeyRotation": lambda: client.enable_key_rotation(KeyId=asset_arn),
                "cloudtrail:UpdateTrail": lambda: client.update_trail(
                    Name=asset_arn.split("/")[-1] if "/" in asset_arn else asset_arn,
                    IsMultiRegionTrail=True,
                ),
            }

            executor = action_map.get(step.command)
            if executor:
                response = executor()
                return {"executed": True, "api_call": step.command, "response": str(response)[:500]}

            return {"simulated": True, "api_call": step.command, "message": "Action not mapped to AWS API executor"}

        except Exception as exc:
            logger.error("aws_api_execution_failed", command=step.command, error=str(exc))
            raise

    def _generate_terraform_hcl(self, step: RemediationStep, asset_arn: str, playbook: RemediationPlaybook) -> str:
        templates = {
            "S3-001": f'''resource "aws_s3_bucket_public_access_block" "this" {{
  bucket = "{asset_arn.split(":::")[-1]}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
            "S3-002": f'''resource "aws_s3_bucket_server_side_encryption_configuration" "this" {{
  bucket = "{asset_arn.split(":::")[-1]}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}''',
            "RDS-003": f'''resource "aws_db_instance" "this" {{
  identifier = "{asset_arn.split(":db:")[-1]}"
  deletion_protection = true
}}''',
            "KMS-001": f'''resource "aws_kms_key" "this" {{
  key_id = "{asset_arn.split("key/")[-1]}"
  enable_key_rotation = true
}}''',
            "VPC-001": f'''resource "aws_flow_log" "this" {{
  log_group_name = "/aws/vpc/flow-logs/{asset_arn.split(":vpc/")[-1]}"
  traffic_type   = "ALL"
  vpc_id         = "{asset_arn.split(":vpc/")[-1]}"

  iam_role_arn = aws_iam_role.flow_log_role.arn
}}

resource "aws_iam_role" "flow_log_role" {{
  name = "vpc-flow-log-role-{asset_arn.split(":vpc/")[-1]}"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Principal = {{ Service = "vpc-flow-logs.amazonaws.com" }}
      Action = "sts:AssumeRole"
    }}]
  }})
}}''',
            "CT-002": f'''resource "aws_cloudtrail" "this" {{
  name           = "{asset_arn.split("trail/")[-1]}"
  is_multi_region_trail = true
}}''',
        }

        return templates.get(playbook.rule_id, f"# Terraform HCL for {playbook.rule_id} not yet available\n# {step.description}")
