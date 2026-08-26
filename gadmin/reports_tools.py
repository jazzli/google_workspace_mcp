"""Read-only Admin SDK Reports tools for access verification and inventory."""

import asyncio
import json
from typing import Optional

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
        raise ValueError("max_results must be between 1 and 100")
    return value


def _sanitize_usage_report(report: dict, include_profile_id: bool) -> dict:
    """Return usage metrics without email addresses, etags, or other identity fields."""
    sanitized = {key: report[key] for key in ("date", "parameters") if key in report}
    entity = report.get("entity", {})
    if entity:
        sanitized_entity = {
            key: entity[key] for key in ("type", "customerId") if key in entity
        }
        if include_profile_id and entity.get("profileId"):
            sanitized_entity["profileId"] = entity["profileId"]
        sanitized["entity"] = sanitized_entity
    return sanitized


@server.tool(title="List Workspace Audit Activities", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors(
    "list_workspace_audit_activities", is_read_only=True, service_type="reports"
)
@require_google_service("reports", "reports_audit_read")
async def list_workspace_audit_activities(
    service,
    user_google_email: str,
    application_name: str = "admin",
    max_results: int = 5,
    target_user_key: str = "all",
    event_name: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    page_token: Optional[str] = None,
) -> str:
    """List a small page of audit event metadata without parameter values or IPs."""
    params = {
        "userKey": target_user_key,
        "applicationName": application_name,
        "maxResults": _bounded_page_size(max_results),
    }
    if event_name:
        params["eventName"] = event_name
    if start_time:
        params["startTime"] = start_time
    if end_time:
        params["endTime"] = end_time
    if page_token:
        params["pageToken"] = page_token

    result = await asyncio.to_thread(service.activities().list(**params).execute)
    activities = []
    for activity in result.get("items", []):
        activity_id = activity.get("id", {})
        actor = activity.get("actor", {})
        activities.append(
            {
                "time": activity_id.get("time"),
                "uniqueQualifier": activity_id.get("uniqueQualifier"),
                "applicationName": activity_id.get("applicationName"),
                "customerId": activity_id.get("customerId"),
                "actor": {
                    key: actor[key]
                    for key in ("profileId", "email", "callerType")
                    if key in actor
                },
                "events": [
                    {
                        "type": event.get("type"),
                        "name": event.get("name"),
                        "parameterNames": [
                            parameter.get("name")
                            for parameter in event.get("parameters", [])
                            if parameter.get("name")
                        ],
                    }
                    for event in activity.get("events", [])
                ],
            }
        )
    response = {"activities": activities, "count": len(activities)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(title="Get Workspace Customer Usage", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors(
    "get_workspace_customer_usage", is_read_only=True, service_type="reports"
)
@require_google_service("reports", "reports_usage_read")
async def get_workspace_customer_usage(
    service,
    user_google_email: str,
    date: str,
    parameters: Optional[str] = None,
    page_token: Optional[str] = None,
) -> str:
    """Get customer-level usage metrics for an explicit YYYY-MM-DD date."""
    params = {"date": date, "customerId": "my_customer"}
    if parameters:
        params["parameters"] = parameters
    if page_token:
        params["pageToken"] = page_token
    result = await asyncio.to_thread(
        service.customerUsageReports().get(**params).execute
    )
    return _json(result)


@server.tool(title="Get Workspace User Usage", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors(
    "get_workspace_user_usage", is_read_only=True, service_type="reports"
)
@require_google_service("reports", "reports_usage_read")
async def get_workspace_user_usage(
    service,
    user_google_email: str,
    date: str,
    target_user_key: str = "all",
    parameters: Optional[str] = None,
    max_results: int = 20,
    page_token: Optional[str] = None,
    include_profile_id: bool = False,
) -> str:
    """Get a bounded page of user usage metrics without email identities.

    ``target_user_key`` may be ``all``, a primary email, or an immutable profile ID.
    Email addresses and opaque pagination tokens are never returned. Immutable
    profile IDs are returned only when ``include_profile_id`` is explicitly enabled
    for a protected inventory workflow. ``hasMore`` indicates whether another page
    exists; callers may supply a separately protected ``page_token`` to continue.
    """
    params = {
        "userKey": target_user_key,
        "date": date,
        "customerId": "my_customer",
        "maxResults": _bounded_page_size(max_results),
    }
    if parameters:
        params["parameters"] = parameters
    if page_token:
        params["pageToken"] = page_token

    result = await asyncio.to_thread(service.userUsageReport().get(**params).execute)
    response = {
        "usageReports": [
            _sanitize_usage_report(report, include_profile_id)
            for report in result.get("usageReports", [])
        ],
        "count": len(result.get("usageReports", [])),
    }
    if result.get("warnings"):
        response["warnings"] = result["warnings"]
    response["hasMore"] = bool(result.get("nextPageToken"))
    return _json(response)
