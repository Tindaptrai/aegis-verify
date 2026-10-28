ERROR_STATUSES = {
    "invalid_request": 400,
    "invalid_username": 400,
    "invalid_display_name": 400,
    "invalid_password": 400,
    "invalid_capabilities": 400,
    "view_required": 400,
    "inherited_capabilities_required": 409,
    "username_exists": 409,
    "user_not_found": 400,
    "self_lock": 409,
    "last_admin": 409,
    "technical_account_readonly": 403,
    "permission_denied": 403,
    "unauthenticated": 401,
    "invalid_credentials": 401,
    "current_password_invalid": 400,
}


class AccountError(ValueError):
    def __init__(self, code: str, status: int):
        if not isinstance(code, str) or type(status) is not int or ERROR_STATUSES.get(code) != status:
            raise ValueError("invalid_account_error")
        self.code = code
        self.status = status
        super().__init__(code)
