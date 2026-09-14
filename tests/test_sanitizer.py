from app.models.device import Vendor
from app.sanitization.sanitizer import sanitize


def test_recoverable_values_are_hidden_by_default_and_available_locally() -> None:
    result = sanitize("username engineer password 0 local-secret\n", Vendor.CISCO_IOS)
    assert "local-secret" not in result.sanitized_text
    assert "local-secret" in result.revealed_text()
    assert result.summary.reversible_count == 1


def test_one_way_hash_is_not_revealed() -> None:
    result = sanitize("enable secret 9 $9$never-crack-this\n", Vendor.CISCO_IOS)
    assert "never-crack-this" not in result.sanitized_text
    assert "never-crack-this" not in result.revealed_text()
