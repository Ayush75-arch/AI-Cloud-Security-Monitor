"""
CloudGuard-AI — Base Scanner
Abstract interface all AWS scanners must implement.
Supports credential injection and dry-run mode.
"""
import abc
from typing import Any

import boto3
import botocore.exceptions

from app.config import settings
from app.utils.exceptions import AWSCredentialsError
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ScanResult:
    """Container for raw assets returned by a scanner."""

    def __init__(self, asset_type: str, asset_id: str, asset_name: str, region: str, raw_config: dict):
        self.asset_type = asset_type
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.region = region
        self.raw_config = raw_config

    def __repr__(self) -> str:
        return f"<ScanResult {self.asset_type}:{self.asset_id}>"


class BaseScanner(abc.ABC):
    """
    Abstract base for all AWS resource scanners.

    Subclasses implement `scan()` which returns a list of ScanResult objects.
    Each scanner is responsible for a single AWS service.
    """

    service_name: str = ""  # e.g. "s3", "iam", "ec2"

    def __init__(self, region: str, account_id: str):
        self.region = region
        self.account_id = account_id
        self._client: Any = None
        self._session: boto3.Session | None = None

    def _get_session(self) -> boto3.Session:
        if self._session:
            return self._session

        kwargs: dict[str, str] = {"region_name": self.region}

        # Use explicit credentials if provided, else fall back to IAM role / env
        if settings.AWS_ACCESS_KEY_ID:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
            if settings.AWS_SESSION_TOKEN:
                kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN

        self._session = boto3.Session(**kwargs)
        return self._session

    def _get_client(self, service: str | None = None) -> Any:
        svc = service or self.service_name
        try:
            return self._get_session().client(svc)
        except botocore.exceptions.NoCredentialsError as exc:
            raise AWSCredentialsError("No credentials found.") from exc
        except botocore.exceptions.ClientError as exc:
            raise AWSCredentialsError(str(exc)) from exc

    @abc.abstractmethod
    async def scan(self) -> list[ScanResult]:
        """Execute scan, return list of discovered assets."""
        ...

    def _paginate(self, client: Any, method: str, result_key: str, **kwargs) -> list:
        """Helper to handle AWS paginated API calls."""
        paginator = client.get_paginator(method)
        results = []
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results
