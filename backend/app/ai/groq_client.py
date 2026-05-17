"""
CloudGuard-AI — Shared Groq HTTP Client
Single place for Groq API config: endpoint, auth, timeout, connection pool.
Used by GROQAdapter (finding analysis) and AIChatService (chat).
"""
import httpx

from app.utils.exceptions import AIProviderError
from app.utils.logger import get_logger

logger = get_logger(__name__)

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"

# Module-level client with connection pooling — not recreated per request.
_client: httpx.AsyncClient | None = None


def get_groq_client(api_key: str) -> httpx.AsyncClient:
    """
    Return a shared AsyncClient. Recreates if api_key changes (e.g. hot-reload).
    For production, manage lifecycle in app lifespan instead.
    """
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=60.0,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _client


async def close_groq_client() -> None:
    """Call during app shutdown to release connections."""
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None


async def groq_chat_completion(
    api_key: str,
    model: str,
    messages: list[dict],
    max_tokens: int = 1000,
    temperature: float = 0.3,
    response_format: dict | None = None,
) -> dict:
    """
    Single function for all Groq chat completions.
    Raises AIProviderError on HTTP or parse errors.
    """
    global _client

    # Recreate client if key changed or client was closed
    if _client is None or _client.is_closed or \
            _client.headers.get("authorization", "") != f"Bearer {api_key}":
        await close_groq_client()
        _client = httpx.AsyncClient(
            timeout=60.0,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    payload: dict = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if response_format:
        payload["response_format"] = response_format

    try:
        response = await _client.post(GROQ_ENDPOINT, json=payload)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        logger.error("groq_http_error", status=exc.response.status_code, body=exc.response.text[:200])
        raise AIProviderError(f"Groq API error {exc.response.status_code}: {exc.response.text[:200]}") from exc
    except Exception as exc:
        logger.error("groq_request_failed", error=str(exc))
        raise AIProviderError(str(exc)) from exc
