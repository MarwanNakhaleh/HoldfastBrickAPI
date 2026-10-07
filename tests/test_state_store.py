"""StateStore is shared between the API service and the holdfastbrick-pair
CLI — two separate processes writing one JSON file. Each process holds its
own StateStore instance, so every instance must see writes made by the
others after it was constructed (real bug: pairing codes minted by the CLI
were invisible to the already-running API, 2026-07-28)."""

from holdfastbrick_api.config import StateStore


def test_pairing_set_by_another_process_is_visible(tmp_path):
    api = StateStore(tmp_path)          # long-running API, loaded at boot
    cli = StateStore(tmp_path)          # holdfastbrick-pair, run later
    cli.set_pairing("123456", expires_at=9_999_999_999)

    pairing = api.get_pairing()
    assert pairing is not None
    assert pairing["code"] == "123456"


def test_token_issued_by_another_process_is_valid(tmp_path):
    api = StateStore(tmp_path)
    other = StateStore(tmp_path)
    token = other.issue_token("iPhone")

    assert api.is_valid_token(token)


def test_save_does_not_clobber_other_process_writes(tmp_path):
    api = StateStore(tmp_path)
    cli = StateStore(tmp_path)
    cli.set_pairing("654321", expires_at=9_999_999_999)

    # The API writes something of its own — this must not erase the
    # pairing the CLI just persisted.
    api.issue_token("iPhone")

    fresh = StateStore(tmp_path)
    pairing = fresh.get_pairing()
    assert pairing is not None
    assert pairing["code"] == "654321"
