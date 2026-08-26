"""Read-only Admin SDK Directory tools for tenant verification and inventory."""

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


def _bounded_page_size(value: int, maximum: int = 200) -> int:
    if value < 1 or value > maximum:
        raise ValueError(f"max_results must be between 1 and {maximum}")
    return value


def _json(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _select(source: dict, fields: tuple[str, ...]) -> dict:
    return {field: source[field] for field in fields if field in source}


@server.tool(title="Get Workspace Customer", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors("get_workspace_customer", is_read_only=True, service_type="admin")
@require_google_service("admin", "admin_customer_read")
async def get_workspace_customer(service, user_google_email: str) -> str:
    """Get canonical tenant identifiers using the ``my_customer`` alias.

    Returns only tenant-identification fields; postal address, phone number, and
    alternate contact email are intentionally omitted.
    """
    result = await asyncio.to_thread(
        service.customers().get(customerKey="my_customer").execute
    )
    return _json(
        _select(
            result,
            ("id", "customerDomain", "customerCreationTime", "language"),
        )
    )


@server.tool(title="List Workspace Domains", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors("list_workspace_domains", is_read_only=True, service_type="admin")
@require_google_service("admin", "admin_domain_read")
async def list_workspace_domains(service, user_google_email: str) -> str:
    """List verified primary/secondary domains and their aliases."""
    result = await asyncio.to_thread(
        service.domains().list(customer="my_customer").execute
    )
    domains = [
        _select(
            domain,
            (
                "domainName",
                "isPrimary",
                "verified",
                "creationTime",
                "domainAliases",
            ),
        )
        for domain in result.get("domains", [])
    ]
    return _json({"domains": domains, "count": len(domains)})


@server.tool(title="List Workspace Users", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors("list_workspace_users", is_read_only=True, service_type="admin")
@require_google_service("admin", "admin_user_read")
async def list_workspace_users(
    service,
    user_google_email: str,
    max_results: int = 10,
    query: Optional[str] = None,
    page_token: Optional[str] = None,
    show_deleted: bool = False,
) -> str:
    """List a bounded page of user metadata without retrieving user content."""
    params = {
        "customer": "my_customer",
        "maxResults": _bounded_page_size(max_results),
        "orderBy": "email",
        "projection": "basic",
        "showDeleted": show_deleted,
    }
    if query:
        params["query"] = query
    if page_token:
        params["pageToken"] = page_token

    result = await asyncio.to_thread(service.users().list(**params).execute)
    users = [
        _select(
            user,
            (
                "id",
                "primaryEmail",
                "name",
                "suspended",
                "archived",
                "orgUnitPath",
                "isAdmin",
                "isDelegatedAdmin",
                "lastLoginTime",
                "creationTime",
                "deletionTime",
                "aliases",
                "nonEditableAliases",
            ),
        )
        for user in result.get("users", [])
    ]
    response = {"users": users, "count": len(users)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(
    title="List Workspace Users for Bounded Review", annotations=READ_ONLY_ANNOTATIONS
)
@handle_http_errors(
    "list_workspace_users_bounded_review", is_read_only=True, service_type="admin"
)
@require_google_service("admin", "admin_user_read")
async def list_workspace_users_bounded_review(
    service,
    user_google_email: str,
    max_results: int = 10,
    query: Optional[str] = None,
    show_deleted: bool = False,
) -> str:
    """List a privacy-minimized first page for a fail-closed user review.

    The response always includes ``hasMore``. Google's opaque page token is
    used only to derive that boolean and is never included in the MCP response.
    Each user contains only ``id``, ``primaryEmail``, ``suspended``,
    ``archived``, ``orgUnitPath``, ``isAdmin``, ``isDelegatedAdmin``, and
    ``isGuestUser`` when those fields are present in Google's response.
    A present page token must be a non-empty string or the call fails closed.
    This method cannot continue pagination; callers must stop when ``hasMore``
    is true and use a separately authorized workflow if more data is required.
    """
    params = {
        "customer": "my_customer",
        "maxResults": _bounded_page_size(max_results),
        "orderBy": "email",
        "projection": "basic",
        "showDeleted": show_deleted,
        "fields": (
            "nextPageToken,users("
            "id,primaryEmail,suspended,archived,orgUnitPath,isAdmin,"
            "isDelegatedAdmin,isGuestUser)"
        ),
    }
    if query:
        params["query"] = query

    result = await asyncio.to_thread(service.users().list(**params).execute)
    if "nextPageToken" in result:
        token = result["nextPageToken"]
        if not isinstance(token, str) or token == "":
            raise ValueError("nextPageToken must be a non-empty string when present")
    else:
        token = None

    users = [
        _select(
            user,
            (
                "id",
                "primaryEmail",
                "suspended",
                "archived",
                "orgUnitPath",
                "isAdmin",
                "isDelegatedAdmin",
                "isGuestUser",
            ),
        )
        for user in result.get("users", [])
    ]
    return _json({"users": users, "count": len(users), "hasMore": bool(token)})


@server.tool(
    title="List Workspace Organizational Units", annotations=READ_ONLY_ANNOTATIONS
)
@handle_http_errors(
    "list_workspace_organizational_units", is_read_only=True, service_type="admin"
)
@require_google_service("admin", "admin_orgunit_read")
async def list_workspace_organizational_units(
    service,
    user_google_email: str,
    org_unit_path: str = "/",
    include_all_descendants: bool = True,
) -> str:
    """List organizational-unit metadata from a specified OU path."""
    result = await asyncio.to_thread(
        service.orgunits()
        .list(
            customerId="my_customer",
            orgUnitPath=org_unit_path,
            type="all" if include_all_descendants else "children",
        )
        .execute
    )
    units = [
        _select(
            unit,
            (
                "orgUnitId",
                "name",
                "orgUnitPath",
                "parentOrgUnitId",
                "parentOrgUnitPath",
                "blockInheritance",
            ),
        )
        for unit in result.get("organizationUnits", [])
    ]
    return _json({"organizationUnits": units, "count": len(units)})


@server.tool(title="List Workspace Groups", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors("list_workspace_groups", is_read_only=True, service_type="admin")
@require_google_service("admin", "admin_group_read")
async def list_workspace_groups(
    service,
    user_google_email: str,
    max_results: int = 10,
    query: Optional[str] = None,
    page_token: Optional[str] = None,
) -> str:
    """List a bounded page of group metadata."""
    params = {
        "customer": "my_customer",
        "maxResults": _bounded_page_size(max_results),
        "orderBy": "email",
    }
    if query:
        params["query"] = query
    if page_token:
        params["pageToken"] = page_token

    result = await asyncio.to_thread(service.groups().list(**params).execute)
    groups = [
        _select(
            group,
            (
                "id",
                "email",
                "name",
                "directMembersCount",
                "adminCreated",
                "aliases",
                "nonEditableAliases",
            ),
        )
        for group in result.get("groups", [])
    ]
    response = {"groups": groups, "count": len(groups)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(title="List Workspace Group Members", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors(
    "list_workspace_group_members", is_read_only=True, service_type="admin"
)
@require_google_service("admin", "admin_group_read")
async def list_workspace_group_members(
    service,
    user_google_email: str,
    group_key: str,
    max_results: int = 10,
    include_derived_membership: bool = False,
    roles: Optional[str] = None,
    page_token: Optional[str] = None,
) -> str:
    """List a bounded page of direct or derived group membership metadata."""
    params = {
        "groupKey": group_key,
        "maxResults": _bounded_page_size(max_results),
        "includeDerivedMembership": include_derived_membership,
    }
    if roles:
        params["roles"] = roles
    if page_token:
        params["pageToken"] = page_token

    result = await asyncio.to_thread(service.members().list(**params).execute)
    members = [
        _select(member, ("id", "email", "role", "type", "status", "delivery_settings"))
        for member in result.get("members", [])
    ]
    response = {"groupKey": group_key, "members": members, "count": len(members)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(title="List Workspace Admin Roles", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors(
    "list_workspace_admin_roles", is_read_only=True, service_type="admin"
)
@require_google_service("admin", "admin_role_read")
async def list_workspace_admin_roles(
    service,
    user_google_email: str,
    max_results: int = 10,
    page_token: Optional[str] = None,
) -> str:
    """List a bounded page of administrative role definitions."""
    params = {
        "customer": "my_customer",
        "maxResults": _bounded_page_size(max_results),
    }
    if page_token:
        params["pageToken"] = page_token
    result = await asyncio.to_thread(service.roles().list(**params).execute)
    roles = [
        _select(
            role,
            (
                "roleId",
                "roleName",
                "roleDescription",
                "isSuperAdminRole",
                "isSystemRole",
            ),
        )
        for role in result.get("items", [])
    ]
    response = {"roles": roles, "count": len(roles)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(
    title="List Workspace Admin Role Assignments", annotations=READ_ONLY_ANNOTATIONS
)
@handle_http_errors(
    "list_workspace_role_assignments", is_read_only=True, service_type="admin"
)
@require_google_service("admin", "admin_role_read")
async def list_workspace_role_assignments(
    service,
    user_google_email: str,
    max_results: int = 10,
    role_id: Optional[str] = None,
    user_key: Optional[str] = None,
    page_token: Optional[str] = None,
) -> str:
    """List a bounded page of administrative role assignments."""
    params = {
        "customer": "my_customer",
        "maxResults": _bounded_page_size(max_results),
    }
    if role_id:
        params["roleId"] = role_id
    if user_key:
        params["userKey"] = user_key
    if page_token:
        params["pageToken"] = page_token

    result = await asyncio.to_thread(service.roleAssignments().list(**params).execute)
    assignments = [
        _select(
            assignment,
            (
                "roleAssignmentId",
                "roleId",
                "assignedTo",
                "assigneeType",
                "scopeType",
                "orgUnitId",
                "condition",
            ),
        )
        for assignment in result.get("items", [])
    ]
    response = {"roleAssignments": assignments, "count": len(assignments)}
    if result.get("nextPageToken"):
        response["nextPageToken"] = result["nextPageToken"]
    return _json(response)


@server.tool(title="List Workspace Custom Schemas", annotations=READ_ONLY_ANNOTATIONS)
@handle_http_errors(
    "list_workspace_custom_schemas", is_read_only=True, service_type="admin"
)
@require_google_service("admin", "admin_schema_read")
async def list_workspace_custom_schemas(service, user_google_email: str) -> str:
    """List user custom-attribute schema definitions, not attribute values."""
    result = await asyncio.to_thread(
        service.schemas().list(customerId="my_customer").execute
    )
    schemas = []
    for schema in result.get("schemas", []):
        item = _select(schema, ("schemaId", "schemaName", "displayName"))
        item["fields"] = [
            _select(
                field,
                (
                    "fieldId",
                    "fieldName",
                    "displayName",
                    "fieldType",
                    "multiValued",
                    "readAccessType",
                ),
            )
            for field in schema.get("fields", [])
        ]
        schemas.append(item)
    return _json({"schemas": schemas, "count": len(schemas)})
