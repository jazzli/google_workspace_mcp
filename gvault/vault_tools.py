"""Read-only Google Vault tools for availability and hold inventory checks."""

import asyncio
import json
from typing import Literal, Optional

from mcp.types import ToolAnnotations

from auth.service_decorator import require_google_service
from core.server import server
from core.utils import handle_http_errors


READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def _json(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _bounded_page_size(value: int) -> int:
    if value < 1 or value > 100:
        raise ValueError("page_size must be between 1 and 100")
    return value


def _select(source: dict, fields: tuple[str, ...]) -> dict:
    return {field: source[field] for field in fields if field in source}


@server.tool(title="List Vault Matters", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors("list_vault_matters", is_read_only=True, service_type="vault")
@require_google_service("vault", "vault_ediscovery_read")
async def list_vault_matters(
    service,
    user_google_email: str,
    page_size: int = 5,
    state: Optional[Literal["OPEN", "CLOSED", "DELETED"]] = None,
    page_token: Optional[str] = None,
) -> str:
    """List a bounded page of Vault matter metadata using BASIC view."""
    params = {"pageSize": _bounded_page_size(page_size), "view": "BASIC"}
    if state:
        params["state"] = state
    if page_token:
        params["pageToken"] = page_token
    result = await asyncio.to_thread(service.matters().list(**params).execute)
    matters = [
        _select(
            matter,
            (
                "matterId",
                "name",
                "state",
                "matterPermission",
            ),
        )
        for matter in result.get("matters", [])
    ]
    response = {"matters": matters, "count": len(matters)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(title="List Vault Holds", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors("list_vault_holds", is_read_only=True, service_type="vault")
@require_google_service("vault", "vault_ediscovery_read")
async def list_vault_holds(
    service,
    user_google_email: str,
    matter_id: str,
    page_size: int = 10,
    page_token: Optional[str] = None,
) -> str:
    """List a bounded page of hold metadata for a specified Vault matter."""
    params = {
        "matterId": matter_id,
        "pageSize": _bounded_page_size(page_size),
        "view": "BASIC",
    }
    if page_token:
        params["pageToken"] = page_token
    result = await asyncio.to_thread(service.matters().holds().list(**params).execute)
    holds = [
        _select(
            hold,
            (
                "holdId",
                "name",
                "updateTime",
                "corpus",
            ),
        )
        for hold in result.get("holds", [])
    ]
    response = {"matterId": matter_id, "holds": holds, "count": len(holds)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)
