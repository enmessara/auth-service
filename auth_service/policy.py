"""RBAC policy: the permission catalogue and the default roles.

Permissions double as OAuth2 scopes. A request is allowed when the permission is
both (a) granted by one of the user's roles *and* (b) present in the token's scope.
"""

PERMISSIONS = {
    "profile:read": "Read own profile",
    "profile:write": "Update own profile",
    "users:read": "List and view users",
    "users:write": "Enable / disable users",
    "roles:manage": "Create roles and assign them to users",
    "audit:read": "Read and verify the audit log",
    "clients:manage": "Register and delete OAuth2 clients",
}

ROLE_DEFS = {
    "user": ("Standard account", ["profile:read", "profile:write"]),
    "auditor": ("Read-only access to users and the audit log",
                ["profile:read", "profile:write", "users:read", "audit:read"]),
    "admin": ("Full access", list(PERMISSIONS)),
}
DEFAULT_ROLE = "user"
