import json
from unittest.mock import Mock

import pytest


def _unwrap(tool):
    fn = getattr(tool, "fn", tool)
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


@pytest.mark.asyncio
async def test_list_vault_matters_uses_basic_bounded_view():
    service = Mock()
    matters_resource = Mock()
    request = Mock()
    service.matters.return_value = matters_resource
    matters_resource.list.return_value = request
    request.execute.return_value = {
        "matters": [{"matterId": "m1", "name": "Matter", "state": "OPEN"}],
        "nextPageToken": "next",
    }

    from gvault.vault_tools import list_vault_matters

    result = json.loads(
        await _unwrap(list_vault_matters)(
            service=service,
            user_google_email="admin@example.com",
            page_size=2,
        )
    )
    assert result["count"] == 1
    assert result["nextPageToken"] == "next"
    matters_resource.list.assert_called_once_with(pageSize=2, view="BASIC")
