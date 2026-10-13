from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from the same directory as this module
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
from typing import Any

import boto3
import pyarrow as pa
import pyarrow.parquet as pq
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


MISSING_OBJECT_CODES = {"404", "NoSuchKey", "NotFound"}


def required_setting(name: str) -> str:
    """Return a required environment setting or raise a clear error."""
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def optional_setting(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def boolean_setting(name: str, default: bool) -> bool:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{name} must be exactly 'True' or 'False'")


def create_s3_client():
    """Create an AWS S3 or S3-compatible client from environment settings."""
    addressing_style = optional_setting("S3_ADDRESSING_STYLE") or "auto"
    if addressing_style not in {"auto", "path", "virtual"}:
        raise ValueError("S3_ADDRESSING_STYLE must be auto, path, or virtual")

    return boto3.client(
        "s3",
        region_name=optional_setting("AWS_REGION"),
        endpoint_url=optional_setting("S3_ENDPOINT_URL"),
        verify=boolean_setting("S3_VERIFY_SSL", True),
        config=Config(s3={"addressing_style": addressing_style}),
    )


def read_parquet_object(
    client: Any,
    bucket: str,
    key: str,
) -> tuple[pa.Table | None, str | None]:
    """Read a Parquet object from S3, returning ``None`` when it does not exist."""
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except ClientError as error:
        error_data = error.response.get("Error", {})
        code = str(error_data.get("Code", ""))
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in MISSING_OBJECT_CODES or status == 404:
            return None, None
        raise RuntimeError(f"Failed to read s3://{bucket}/{key}: {code or error}") from error
    except BotoCoreError as error:
        raise RuntimeError(f"Failed to read s3://{bucket}/{key}") from error

    body = response["Body"]
    try:
        payload = body.read()
    finally:
        body.close()

    if not payload:
        raise ValueError(f"S3 object is empty: s3://{bucket}/{key}")
    try:
        table = pq.read_table(pa.BufferReader(payload))
    except (pa.ArrowException, OSError) as error:
        raise ValueError(f"S3 object is not a readable Parquet file: s3://{bucket}/{key}") from error

    etag = str(response.get("ETag", "")).strip('"') or None
    return table, etag


def parquet_bytes(table: pa.Table, compression: str) -> bytes:
    """Serialize an Arrow table to Parquet entirely in memory."""
    sink = pa.BufferOutputStream()
    pq.write_table(table, sink, compression=compression)
    return sink.getvalue().to_pybytes()


def write_parquet_object(
    client: Any,
    bucket: str,
    key: str,
    table: pa.Table,
    compression: str,
) -> dict[str, Any]:
    """Replace an S3 object with a complete Parquet table and verify its size."""
    import hashlib
    import hmac
    from datetime import datetime
    import requests

    payload = parquet_bytes(table, compression)
    endpoint_url = optional_setting("S3_ENDPOINT_URL") or "https://s3.amazonaws.com"
    region = optional_setting("AWS_REGION") or "us-east-1"
    access_key = os.getenv("AWS_ACCESS_KEY_ID", "")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "")

    # Build S3-compatible PUT request manually
    service = "s3"
    host = endpoint_url.replace("https://", "").replace("http://", "").split("/")[0]
    canonical_uri = f"/{bucket}/{key}"
    t = datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    # Build canonical request
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    # Build string to sign
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    # Build signature
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signing_key = sign(sign(sign(sign(b"AWS4" + secret_key.encode("utf-8"), date_stamp), region), service), "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # Build authorization header
    authorization_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    headers = {
        "Content-Type": "application/vnd.apache.parquet",
        "Content-Length": str(len(payload)),
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
    }

    url = f"{endpoint_url}/{bucket}/{key}"

    try:
        response = requests.put(url, data=payload, headers=headers, verify=boolean_setting("S3_VERIFY_SSL", True))
        response.raise_for_status()

        remote = client.head_object(Bucket=bucket, Key=key)
    except Exception as error:
        raise RuntimeError(f"Failed to write s3://{bucket}/{key}: {error}") from error

    remote_size = int(remote["ContentLength"])
    if remote_size != len(payload):
        raise RuntimeError(
            f"Size mismatch for s3://{bucket}/{key}: "
            f"sent={len(payload)}, stored={remote_size}"
        )

    return {
        "size_bytes": remote_size,
        "etag": str(remote.get("ETag") or "").strip('"') or None,
    }
