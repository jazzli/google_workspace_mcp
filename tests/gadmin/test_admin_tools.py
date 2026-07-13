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
