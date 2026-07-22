import json
from unittest.mock import Mock

import pytest


def _unwrap(tool):
    fn = getattr(tool, "fn", tool)
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


@pytest.mark.asyncio
async def test_get_workspace_customer_omits_contact_fields():
    service = Mock()
    customers = Mock()
    request = Mock()
    service.customers.return_value = customers
    customers.get.return_value = request
    request.execute.return_value = {
        "id": "C0123",
        "customerDomain": "example.com",
        "language": "en",
        "alternateEmail": "private@example.com",
        "phoneNumber": "+1-555-0100",
        "postalAddress": {"countryCode": "US"},
    }

    from gadmin.directory_tools import get_workspace_customer

    result = json.loads(
        await _unwrap(get_workspace_customer)(
            service=service, user_google_email="admin@example.com"
        )
    )
    assert result == {
        "customerDomain": "example.com",
        "id": "C0123",
        "language": "en",
    }
    customers.get.assert_called_once_with(customerKey="my_customer")


@pytest.mark.asyncio
async def test_list_workspace_users_is_bounded_and_sanitized():
    service = Mock()
    users_resource = Mock()
    request = Mock()
    service.users.return_value = users_resource
    users_resource.list.return_value = request
    request.execute.return_value = {
        "users": [
            {
                "id": "u1",
                "primaryEmail": "person@example.com",
                "suspended": True,
                "thumbnailPhotoUrl": "https://example.invalid/photo",
            }
        ],
        "nextPageToken": "next",
    }

    from gadmin.directory_tools import list_workspace_users

    result = json.loads(
        await _unwrap(list_workspace_users)(
            service=service,
            user_google_email="admin@example.com",
            max_results=3,
        )
    )
    assert result["count"] == 1
    assert result["nextPageToken"] == "next"
    assert "thumbnailPhotoUrl" not in result["users"][0]
    users_resource.list.assert_called_once_with(
        customer="my_customer",
        maxResults=3,
        orderBy="email",
        projection="basic",
        showDeleted=False,
    )


@pytest.mark.asyncio
async def test_bounded_review_reports_complete_five_user_set_and_minimizes_fields():
    service = Mock()
    users_resource = Mock()
    request = Mock()
    service.users.return_value = users_resource
    users_resource.list.return_value = request
    request.execute.return_value = {
        "users": [
            {
                "id": f"u{i}",
                "primaryEmail": f"person{i}@example.com",
                "suspended": False,
                "archived": False,
                "orgUnitPath": "/",
                "isAdmin": False,
                "isDelegatedAdmin": False,
                "isGuestUser": False,
                "name": {"fullName": f"Person {i}"},
                "lastLoginTime": "2026-07-20T00:00:00Z",
                "creationTime": "2020-01-01T00:00:00Z",
                "recoveryEmail": f"recovery{i}@example.net",
                "recoveryPhone": "+65 0000 0000",
                "isEnrolledIn2Sv": True,
                "customSchemas": {"private": {"value": "secret"}},
            }
            for i in range(5)
        ]
    }

    from gadmin.directory_tools import list_workspace_users_bounded_review

    result = json.loads(
        await _unwrap(list_workspace_users_bounded_review)(
            service=service,
            user_google_email="admin@example.com",
            max_results=5,
            query="isSuspended=false isArchived=false isGuest=false",
        )
    )
    assert result["count"] == 5
    assert result["hasMore"] is False
    assert all(user["isGuestUser"] is False for user in result["users"])
    assert all(
        set(user)
        == {
            "id",
            "primaryEmail",
            "suspended",
            "archived",
            "orgUnitPath",
            "isAdmin",
            "isDelegatedAdmin",
            "isGuestUser",
        }
        for user in result["users"]
    )
    serialized = json.dumps(result)
    assert "nextPageToken" not in result
    assert "recovery" not in serialized
    assert "isEnrolledIn2Sv" not in serialized
    assert "customSchemas" not in serialized
    assert "lastLoginTime" not in serialized
    users_resource.list.assert_called_once_with(
        customer="my_customer",
        maxResults=5,
        orderBy="email",
        projection="basic",
        showDeleted=False,
        fields=(
            "nextPageToken,users("
            "id,primaryEmail,suspended,archived,orgUnitPath,isAdmin,"
            "isDelegatedAdmin,isGuestUser)"
        ),
        query="isSuspended=false isArchived=false isGuest=false",
    )


@pytest.mark.asyncio
async def test_bounded_review_reports_more_without_returning_raw_token():
    service = Mock()
    users_resource = Mock()
    request = Mock()
    service.users.return_value = users_resource
    users_resource.list.return_value = request
    users = [
        {
            "id": f"u{i}",
            "primaryEmail": f"person{i}@example.com",
            "isGuestUser": False,
        }
        for i in range(5)
    ]
    request.execute.return_value = {
        "users": users,
        "nextPageToken": "opaque-sensitive-token",
    }

    from gadmin.directory_tools import list_workspace_users_bounded_review

    serialized = await _unwrap(list_workspace_users_bounded_review)(
        service=service,
        user_google_email="admin@example.com",
        max_results=5,
    )
    result = json.loads(serialized)
    assert result["count"] == 5
    assert result["hasMore"] is True
    assert "nextPageToken" not in result
    assert "opaque-sensitive-token" not in serialized


@pytest.mark.asyncio
async def test_bounded_review_empty_result_has_explicit_completion_state():
    service = Mock()
    users_resource = Mock()
    request = Mock()
    service.users.return_value = users_resource
    users_resource.list.return_value = request
    request.execute.return_value = {"users": []}

    from gadmin.directory_tools import list_workspace_users_bounded_review

    result = json.loads(
        await _unwrap(list_workspace_users_bounded_review)(
            service=service,
            user_google_email="admin@example.com",
            max_results=1,
            query="email:never-match@example.com",
        )
    )
    assert result == {"count": 0, "hasMore": False, "users": []}


@pytest.mark.asyncio
async def test_bounded_review_rejects_non_string_page_token_without_echoing_it():
    service = Mock()
    users_resource = Mock()
    request = Mock()
    service.users.return_value = users_resource
    users_resource.list.return_value = request
    from gadmin.directory_tools import list_workspace_users_bounded_review

    for token in (None, "", {"unexpected": "raw-token-value"}):
        request.execute.return_value = {"users": [], "nextPageToken": token}
        with pytest.raises(
            ValueError, match="nextPageToken must be a non-empty string"
        ) as error:
            await _unwrap(list_workspace_users_bounded_review)(
                service=service,
                user_google_email="admin@example.com",
            )
        assert "raw-token-value" not in str(error.value)


@pytest.mark.asyncio
async def test_bounded_review_live_tool_declaration_is_explicit_and_no_token_input():
    from core.server import server
    from gadmin import directory_tools  # noqa: F401

    tool = next(
        item
        for item in await server.list_tools(run_middleware=False)
        if item.name == "list_workspace_users_bounded_review"
    )
    assert tool.description is not None
    for field in (
        "id",
        "primaryEmail",
        "suspended",
        "archived",
        "orgUnitPath",
        "isAdmin",
        "isDelegatedAdmin",
        "isGuestUser",
        "hasMore",
    ):
        assert f"``{field}``" in tool.description
    assert "never included in the MCP response" in tool.description
    assert set(tool.parameters["properties"]) == {
        "user_google_email",
        "max_results",
        "query",
        "show_deleted",
    }
    assert "page_token" not in tool.parameters["properties"]


@pytest.mark.asyncio
async def test_list_audit_activities_omits_parameter_values_and_ip():
    service = Mock()
    activities_resource = Mock()
    request = Mock()
    service.activities.return_value = activities_resource
    activities_resource.list.return_value = request
    request.execute.return_value = {
        "items": [
            {
                "id": {"time": "2026-01-01T00:00:00Z", "customerId": "C0123"},
                "ipAddress": "192.0.2.1",
                "actor": {"email": "admin@example.com"},
                "events": [
                    {
                        "type": "USER_SETTINGS",
                        "name": "CREATE_USER",
                        "parameters": [
                            {"name": "USER_EMAIL", "value": "person@example.com"}
                        ],
                    }
                ],
            }
        ]
    }

    from gadmin.reports_tools import list_workspace_audit_activities

    result = json.loads(
        await _unwrap(list_workspace_audit_activities)(
            service=service, user_google_email="admin@example.com"
        )
    )
    serialized = json.dumps(result)
    assert "192.0.2.1" not in serialized
    assert "person@example.com" not in serialized
    assert result["activities"][0]["events"][0]["parameterNames"] == ["USER_EMAIL"]


@pytest.mark.asyncio
async def test_get_workspace_user_usage_is_bounded_and_redacts_identity():
    service = Mock()
    usage_resource = Mock()
    request = Mock()
    service.userUsageReport.return_value = usage_resource
    usage_resource.get.return_value = request
    request.execute.return_value = {
        "usageReports": [
            {
                "date": "2026-07-12",
                "entity": {
                    "type": "USER",
                    "customerId": "C0123",
                    "userEmail": "person@example.com",
                    "profileId": "profile-1",
                },
                "etag": "private-etag",
                "parameters": [
                    {"name": "drive:num_owned_items_delta", "intValue": "7"}
                ],
            }
        ],
        "nextPageToken": "next",
    }

    from gadmin.reports_tools import get_workspace_user_usage

    result = json.loads(
        await _unwrap(get_workspace_user_usage)(
            service=service,
            user_google_email="admin@example.com",
            date="2026-07-12",
            target_user_key="all",
            parameters="drive:num_owned_items_delta",
            max_results=5,
        )
    )
    serialized = json.dumps(result)
    assert result["count"] == 1
    assert result["hasMore"] is True
    assert "nextPageToken" not in result
    assert "person@example.com" not in serialized
    assert "profile-1" not in serialized
    assert "private-etag" not in serialized
    assert result["usageReports"][0]["parameters"][0]["intValue"] == "7"
    usage_resource.get.assert_called_once_with(
        userKey="all",
        date="2026-07-12",
        customerId="my_customer",
        maxResults=5,
        parameters="drive:num_owned_items_delta",
    )


@pytest.mark.asyncio
async def test_get_workspace_user_usage_profile_id_requires_opt_in():
    service = Mock()
    usage_resource = Mock()
    request = Mock()
    service.userUsageReport.return_value = usage_resource
    usage_resource.get.return_value = request
    request.execute.return_value = {
        "usageReports": [
            {
                "date": "2026-07-12",
                "entity": {
                    "type": "USER",
                    "customerId": "C0123",
                    "userEmail": "person@example.com",
                    "profileId": "profile-1",
                },
            }
        ]
    }

    from gadmin.reports_tools import get_workspace_user_usage

    result = json.loads(
        await _unwrap(get_workspace_user_usage)(
            service=service,
            user_google_email="admin@example.com",
            date="2026-07-12",
            target_user_key="all",
            include_profile_id=True,
        )
    )
    assert result["usageReports"][0]["entity"]["profileId"] == "profile-1"
    assert "userEmail" not in result["usageReports"][0]["entity"]
