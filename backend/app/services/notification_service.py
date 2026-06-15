"""
CloudGuard-AI — Notification Service
Multi-channel alerting for security findings: Slack, Email, Webhook.
Supports per-channel configuration with templated messages.
"""
from dataclasses import dataclass, field

import httpx

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class NotificationChannel:
    name: str
    enabled: bool = True

    def format_message(self, findings: list[dict]) -> str:  # type: ignore[empty-body]
        ...


@dataclass
class SlackChannel(NotificationChannel):
    webhook_url: str = ""
    name: str = "slack"

    def format_message(self, findings: list[dict]) -> dict:  # type: ignore[override]
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "CloudGuard-AI Security Alert"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Found *{len(critical)} critical* and *{len(high)} high* severity findings.",
                },
            },
            {"type": "divider"},
        ]

        for f in (critical + high)[:10]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{f.get('rule_id', 'N/A')}: {f.get('title', 'N/A')}*\n"
                            f"Severity: *{f.get('severity', '').upper()}* on `{f.get('asset_name', '')}`\n"
                            f"{f.get('description', '')[:200]}",
                },
            })

        if len(findings) > 10:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"*{len(findings) - 10}* additional findings not shown.",
                }],
            })

        return {"blocks": blocks}


@dataclass
class EmailChannel(NotificationChannel):
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    to_emails: list[str] = field(default_factory=list)
    from_email: str = "cloudguard@localhost"
    name: str = "email"


@dataclass
class WebhookChannel(NotificationChannel):
    url: str = ""
    headers: dict = field(default_factory=dict)
    name: str = "webhook"

    def format_payload(self, findings: list[dict]) -> dict:
        return {
            "event": "security_findings",
            "source": "cloudguard-ai",
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
            "high_count": sum(1 for f in findings if f.get("severity") == "high"),
            "findings": [
                {
                    "rule_id": f.get("rule_id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "asset_name": f.get("asset_name"),
                    "description": f.get("description"),
                }
                for f in findings[:50]
            ],
        }


class NotificationService:

    def __init__(self):
        self._channels: list[NotificationChannel] = []
        self._init_channels()

    def _init_channels(self):
        slack_url = settings.SLACK_WEBHOOK_URL or ""
        if slack_url:
            self._channels.append(SlackChannel(webhook_url=slack_url))

        webhook_url = settings.CUSTOM_WEBHOOK_URL or ""
        if webhook_url:
            headers = settings.CUSTOM_WEBHOOK_HEADERS or {}
            self._channels.append(WebhookChannel(url=webhook_url, headers=headers))

        if settings.SMTP_SERVER and settings.EMAIL_TO:
            self._channels.append(EmailChannel(
                smtp_server=settings.SMTP_SERVER,
                smtp_port=settings.SMTP_PORT or 587,
                smtp_user=settings.SMTP_USER or "",
                smtp_password=settings.SMTP_PASSWORD or "",
                to_emails=settings.EMAIL_TO.split(",") if isinstance(settings.EMAIL_TO, str) else settings.EMAIL_TO,
                from_email=settings.EMAIL_FROM or "cloudguard@localhost",
            ))

    async def send_alert(self, findings: list[dict]) -> int:
        """Send an alert across all configured channels. Returns count of successful sends."""
        successes = 0

        for channel in self._channels:
            try:
                if isinstance(channel, SlackChannel):
                    await self._send_slack(channel, findings)
                    successes += 1
                elif isinstance(channel, WebhookChannel):
                    await self._send_webhook(channel, findings)
                    successes += 1
                elif isinstance(channel, EmailChannel):
                    await self._send_email(channel, findings)
                    successes += 1
                logger.info("notification_sent", channel=channel.name)
            except Exception as exc:
                logger.error("notification_failed", channel=channel.name, error=str(exc))

        return successes

    async def _send_slack(self, channel: SlackChannel, findings: list[dict]):
        payload = channel.format_message(findings)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(channel.webhook_url, json=payload)
            response.raise_for_status()

    async def _send_webhook(self, channel: WebhookChannel, findings: list[dict]):
        payload = channel.format_payload(findings)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                channel.url,
                json=payload,
                headers=channel.headers,
            )
            response.raise_for_status()

    async def _send_email(self, channel: EmailChannel, findings: list[dict]):
        import smtplib
        from email.mime.text import MIMEText

        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")

        body_lines = [
            "CloudGuard-AI Security Alert",
            "=" * 40,
            f"Total Findings: {len(findings)}",
            f"Critical: {critical}",
            f"High: {high}",
            "",
            "Findings:",
            "-" * 40,
        ]
        for f in findings[:30]:
            body_lines.append(f"[{f.get('severity', '').upper()}] {f.get('rule_id')}: {f.get('title')} on {f.get('asset_name')}")

        msg = MIMEText("\n".join(body_lines))
        msg["Subject"] = f"CloudGuard-AI: {critical}C / {high}H Security Findings"
        msg["From"] = channel.from_email
        msg["To"] = ", ".join(channel.to_emails)

        with smtplib.SMTP(channel.smtp_server, channel.smtp_port) as server:
            if channel.smtp_user:
                server.starttls()
                server.login(channel.smtp_user, channel.smtp_password)
            server.sendmail(channel.from_email, channel.to_emails, msg.as_string())
