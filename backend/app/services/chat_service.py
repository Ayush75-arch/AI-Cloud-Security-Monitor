"""
CloudGuard-AI — AI Security Copilot (Chat Assistant)
Natural language Q&A about cloud security findings.

Example queries:
  "Why is this IAM policy dangerous?"
  "How would an attacker exploit open SSH?"
  "What does CIS 1.16 mean?"
  "How do I fix the S3 public access issue?"
"""
import json
from dataclasses import dataclass

from app.config import refresh_settings, settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are CloudGuard-AI, an expert cloud security engineer and analyst.
You help security teams understand misconfigurations, attack scenarios, and remediation steps.

You have deep expertise in:
- AWS security (S3, IAM, EC2, VPC, security groups)
- Compliance frameworks (CIS Benchmarks, NIST SP 800-53, PCI-DSS, ISO 27001, GDPR)
- Attack techniques (MITRE ATT&CK for Cloud)
- Terraform and Infrastructure-as-Code security
- Real-world breach case studies

When answering:
- Be technical and specific, not generic
- Reference real CVEs, techniques, or breach examples when relevant
- Always provide actionable remediation steps
- Keep responses concise but complete (3-5 paragraphs max)
- Use plain text, not markdown headers

If the user asks about a specific finding or rule ID (like S3-001, IAM-001), explain it in detail."""


@dataclass
class ChatMessage:
    role: str   # "user" or "assistant"
    content: str


@dataclass
class ChatResponse:
    message: str
    suggested_questions: list[str]


class AIChatService:
    """
    Conversational AI assistant for cloud security questions.
    Maintains conversation history for multi-turn dialogue.
    Falls back to rule-based responses when no AI key configured.
    """

    async def chat(
        self,
        user_message: str,
        history: list[dict],
        context: dict | None = None,
    ) -> ChatResponse:
        """
        Process a user message and return AI response.

        Args:
            user_message: User's question
            history: Previous messages [{role, content}]
            context: Optional finding/scan context to inject
        """
        # Build context-enriched message
        enriched = self._enrich_message(user_message, context)
        current_settings = refresh_settings()

        if current_settings.AI_PROVIDER == "groq" and current_settings.GROQ_API_KEY:
            return await self._groq_chat(enriched, history, current_settings)
        elif current_settings.AI_PROVIDER == "local":
            return await self._local_chat(enriched, history)
        else:
            return self._fallback_response(user_message)

    async def _groq_chat(self, message: str, history: list[dict], current_settings) -> ChatResponse:
        import httpx
        headers = {
            "Authorization": f"Bearer {current_settings.GROQ_API_KEY}",
            "Content-Type": "application/json",
        }

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for h in history[-10:]:
            role = h.get("role")
            content = h.get("content")
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": message})

        try:
            async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    json={
                        "model": current_settings.GROQ_MODEL,
                        "messages": messages,
                        "max_tokens": 800,
                        "temperature": 0.4,
                    },
                )
                resp.raise_for_status()
                answer = self._parse_groq_response(resp.json())
                return ChatResponse(
                    message=answer,
                    suggested_questions=self._suggest_questions(message),
                )
        except httpx.HTTPStatusError as exc:
            detail = self._groq_error_detail(exc.response)
            logger.error(
                "chat_groq_http_error",
                status_code=exc.response.status_code,
                detail=detail,
            )
            return self._provider_error_response(message, exc.response.status_code, detail)
        except httpx.RequestError as exc:
            logger.error("chat_groq_connection_error", error=str(exc))
            return self._provider_unavailable_response(message)
        except Exception as exc:
            logger.error("chat_groq_error", error=str(exc))
            return self._provider_unavailable_response(message)

    @staticmethod
    def _parse_groq_response(payload: dict) -> str:
        output = payload.get("output")
        if isinstance(output, str):
            return output
        choices = payload.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") if isinstance(choices[0], dict) else None
            if isinstance(message, dict):
                return message.get("content", "")
        if isinstance(output, list) and output:
            first = output[0]
            if isinstance(first, dict):
                if "output_text" in first:
                    return first["output_text"]
                if "content" in first and isinstance(first["content"], list):
                    text_parts = [item.get("text", "") for item in first["content"] if isinstance(item, dict)]
                    return "".join(text_parts)
        return payload.get("output_text", "") or ""

    @staticmethod
    def _groq_error_detail(response) -> str:
        try:
            payload = response.json()
        except ValueError:
            return response.text[:300]

        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            return str(error.get("message") or error)
        return str(payload)[:300]

    @staticmethod
    def _provider_error_response(
        message: str,
        status_code: int | None = None,
        detail: str | None = None,
    ) -> ChatResponse:
        if status_code in {401, 403}:
            response = "Groq rejected the request. Check that GROQ_API_KEY is valid and active."
        elif status_code == 404:
            response = (
                "Groq rejected the model name. Set GROQ_MODEL to an active model such as "
                "llama-3.3-70b-versatile."
            )
        elif status_code == 429:
            response = "Groq rate-limited the request. Wait a moment and try again."
        elif detail:
            response = f"Groq is configured, but the API request failed: {detail}"
        else:
            response = (
                "Groq is configured, but the API request failed. Check that GROQ_MODEL is available "
                "for your account and that the API key is valid, then try again."
            )
        return ChatResponse(
            message=response,
            suggested_questions=AIChatService._suggest_questions(message),
        )

    @staticmethod
    def _provider_unavailable_response(message: str) -> ChatResponse:
        response = AIChatService._fallback_response(message)
        response.message = (
            f"{response.message}\n\n"
            "Note: Groq is currently unreachable, so this response used CloudGuard-AI's built-in guidance."
        )
        return response

    async def _local_chat(self, message: str, history: list[dict]) -> ChatResponse:
        import httpx
        # Build conversation context for local LLM
        conv = f"System: {SYSTEM_PROMPT}\n\n"
        for h in history[-6:]:
            conv += f"{h['role'].capitalize()}: {h['content']}\n"
        conv += f"User: {message}\nAssistant:"

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{settings.LOCAL_LLM_BASE_URL}/api/generate",
                    json={"model": settings.LOCAL_LLM_MODEL, "prompt": conv, "stream": False},
                )
                resp.raise_for_status()
                answer = resp.json().get("response", "")
                return ChatResponse(
                    message=answer,
                    suggested_questions=self._suggest_questions(message),
                )
        except Exception as exc:
            logger.warning("chat_local_llm_error", error=str(exc))
            return self._fallback_response(message)

    @staticmethod
    def _enrich_message(message: str, context: dict | None) -> str:
        if not context:
            return message
        ctx_str = "\n".join(f"- {k}: {v}" for k, v in context.items() if v)
        return f"{message}\n\nContext:\n{ctx_str}"

    @staticmethod
    def _fallback_response(message: str) -> ChatResponse:
        """Rule-based fallback when no AI provider is configured."""
        msg = message.lower()

        responses = {
            ("s3", "public"): (
                "A public S3 bucket exposes all stored objects to the internet without authentication. "
                "Attackers enumerate bucket names using tools like S3Scanner or via certificate transparency logs. "
                "Once found, they can download all files including database backups, application configs, and PII. "
                "Fix: Enable S3 Block Public Access at both the bucket and account level, and audit your bucket policy using IAM Access Analyzer."
            ),
            ("iam", "wildcard"): (
                "An IAM policy with Action:* and Resource:* grants the same permissions as the root account. "
                "Any principal with this policy can create admin users, disable CloudTrail, delete all resources, and exfiltrate all data. "
                "This violates CIS Benchmark 1.16 and NIST AC-6 (Least Privilege). "
                "Fix: Use IAM Access Analyzer to generate a least-privilege policy based on actual usage. Never use Action:*."
            ),
            ("ssh", "port 22", "open ssh"): (
                "Open SSH (port 22) to 0.0.0.0/0 means your instance is exposed to automated brute-force attacks within minutes of launch. "
                "Attackers use tools like Masscan to find open SSH ports across the entire IPv4 space continuously. "
                "Fix: Remove the 0.0.0.0/0 rule and use AWS Systems Manager Session Manager for shell access instead — no port 22 required at all."
            ),
            ("mfa",): (
                "Without MFA, a single phished or leaked password gives full console access. "
                "AWS phishing campaigns are extremely common — attackers send fake 'unusual activity' emails that harvest credentials. "
                "Fix: Enforce MFA using an IAM policy that denies all console actions unless aws:MultiFactorAuthPresent is true."
            ),
            ("cis",): (
                "CIS AWS Foundations Benchmark is a set of security best practices published by the Center for Internet Security. "
                "It covers IAM, logging, monitoring, networking, and storage. "
                "Organizations use it as a baseline for AWS security audits and compliance certifications. "
                "Each control maps to a specific configuration check — CloudGuard scans for all Level 1 and Level 2 controls."
            ),
            ("breach", "attacker", "attackers", "cloud environment"): (
                "Attackers usually breach cloud environments through exposed credentials, over-permissive IAM, public services, and weak logging. "
                "A common path starts with leaked access keys in source code, CI variables, developer laptops, or package artifacts. "
                "Once inside, attackers enumerate IAM permissions, look for privilege escalation paths, disable or evade logging, and search S3, snapshots, secrets stores, and databases for data they can exfiltrate. "
                "Reduce the risk by enforcing MFA, rotating exposed keys, using least-privilege IAM, blocking public storage access, limiting inbound management ports, and alerting on CloudTrail events such as new access keys, policy attachment, AssumeRole spikes, and logging changes."
            ),
            ("critical", "misconfiguration"): (
                "The most critical AWS misconfigurations are public S3 buckets, IAM wildcard permissions, exposed SSH or RDP, disabled CloudTrail, missing MFA, unencrypted sensitive data stores, and public database endpoints. "
                "Prioritize anything that combines internet exposure with sensitive data or privilege escalation. "
                "A practical triage order is: fix public access first, remove broad IAM permissions next, restore logging and alerting, then enforce encryption and backup controls. "
                "For each fix, verify with AWS IAM Access Analyzer, Security Hub, Config rules, and a follow-up CloudGuard scan."
            ),
            ("compliance", "framework"): (
                "Start with CIS AWS Foundations Benchmark for concrete cloud hardening controls, then map those fixes to the frameworks your business must prove: NIST 800-53 for broad security governance, PCI-DSS for cardholder data, HIPAA for healthcare data, ISO 27001 for an ISMS program, and GDPR for personal data protection. "
                "CIS is usually the best engineering baseline because it translates directly into checks for IAM, logging, monitoring, storage, and networking. "
                "After that, prioritize frameworks based on regulated data, customer commitments, and audit deadlines."
            ),
        }

        for keywords, response in responses.items():
            if any(kw in msg for kw in keywords):
                return ChatResponse(
                    message=response,
                    suggested_questions=AIChatService._suggest_questions(message),
                )

        return ChatResponse(
            message=(
                "I can help you understand cloud security findings, attack scenarios, and remediation steps. "
                "Try asking about specific findings like 'Why is an open S3 bucket dangerous?' or "
                "'How would an attacker exploit IAM wildcard permissions?' or 'What does CIS 1.16 mean?'."
            ),
            suggested_questions=AIChatService._suggest_questions(message),
        )

    @staticmethod
    def _suggest_questions(message: str) -> list[str]:
        """Context-aware follow-up question suggestions."""
        msg = message.lower()
        if "s3" in msg:
            return [
                "How would an attacker find my S3 buckets?",
                "What data is most at risk in a public S3 bucket?",
                "How do I enforce encryption on all S3 buckets?",
            ]
        if "iam" in msg:
            return [
                "How do I generate a least-privilege IAM policy?",
                "What is the blast radius of a compromised admin IAM user?",
                "How does privilege escalation work in AWS IAM?",
            ]
        if "ssh" in msg or "security group" in msg:
            return [
                "What is AWS Systems Manager Session Manager?",
                "How do I audit all open ports across my AWS account?",
                "What is a bastion host and when should I use one?",
            ]
        return [
            "What are the most critical AWS misconfigurations?",
            "How do attackers typically breach cloud environments?",
            "What compliance frameworks should I prioritize?",
        ]
