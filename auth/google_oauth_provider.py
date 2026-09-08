"""Application-owned discovery compatibility for the locked Google OAuth proxy."""

from fastmcp.server.auth.providers.google import GoogleProvider
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from starlette.routing import Route


class WorkspaceGoogleProvider(GoogleProvider):
    """Advertise the public DCR clients FastMCP already accepts.

    FastMCP 3.2.4 stores downstream DCR clients with auth method ``none``,
    but MCP SDK 1.27.0's metadata builder lists only secret-based methods.
    Rebuild only that metadata route with the same builder/options as the
    locked stack, preserving CIMD metadata and the existing advertised methods.
    Registration, consent, PKCE, token handlers and upstream auth are unchanged.

    Recheck this compatibility adapter when upgrading either dependency.
    """

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        for index, route in enumerate(routes):
            if not isinstance(route, Route) or not (
                route.path == "/.well-known/oauth-authorization-server"
                or route.path.startswith("/.well-known/oauth-authorization-server/")
            ):
                continue

            assert self.base_url is not None
            metadata = build_metadata(
                self.base_url,
                self.service_documentation_url,
                self.client_registration_options or ClientRegistrationOptions(),
                self.revocation_options or RevocationOptions(),
            )
            if self._cimd_manager is not None:
                metadata.client_id_metadata_document_supported = True
            methods = list(metadata.token_endpoint_auth_methods_supported or [])
            if "none" not in methods:
                methods.append("none")
            metadata.token_endpoint_auth_methods_supported = methods
            routes[index] = Route(
                path=route.path,
                endpoint=cors_middleware(
                    MetadataHandler(metadata).handle, ["GET", "OPTIONS"]
                ),
                methods=route.methods,
                name=route.name,
                include_in_schema=route.include_in_schema,
            )
        return routes
