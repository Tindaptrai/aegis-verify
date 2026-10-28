"""Public catalog errors contain fixed vocabulary only."""

ERROR_CODES = frozenset({
    "invalid_zip", "package_too_large", "too_many_members", "member_too_large",
    "expanded_too_large", "compression_ratio", "invalid_path", "duplicate_member",
    "unsupported_member", "encrypted_member", "unsupported_compression", "nested_archive",
    "invalid_utf8", "invalid_json", "invalid_metadata", "inventory_mismatch", "hash_mismatch",
    "invalid_scenario", "scenario_mismatch", "invalid_profile", "profile_mismatch",
    "invalid_request", "not_found", "version_conflict", "content_conflict", "storage_unavailable",
    "forbidden", "unauthenticated", "invalid_transition", "package_not_found",
})


class CatalogError(ValueError):
    def __init__(self, code, status=400, codes=None):
        self.code = code if code in ERROR_CODES else "invalid_request"
        self.status = status if type(status) is int and 400 <= status <= 599 else 400
        self.codes = list(dict.fromkeys(
            item for item in (codes if isinstance(codes, (list, tuple)) else [])
            if isinstance(item, str) and item in ERROR_CODES
        ))[:32]
        super().__init__(self.code)
