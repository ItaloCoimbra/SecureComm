"""E2EE properties exercised with synthetic local accounts and temporary vaults."""

import copy
import json

import pytest


def paired(tmp_path):
    from core.e2ee import Messenger
    from core.identity import IdentityVault

    a = IdentityVault.create(tmp_path / "alice.vault", "synthetic-test-passphrase-a")
    b = IdentityVault.create(tmp_path / "bob.vault", "synthetic-test-passphrase-b")
    ai, bi = a.public_identity(), b.public_identity()
    a.add_contact("bob", bi, bi["id"])
    b.add_contact("alice", ai, ai["id"])
    return a, b, Messenger(a), Messenger(b)


def claim_for(messenger):
    bundle = messenger.issue_prekeys(1)
    return {"identity": bundle["identity"], "prekey": bundle["prekeys"][0]}


def test_initial_message_receipt_and_reply(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        assert alice.needs_prekey("bob")
        envelope = alice.prepare_message("bob", "synthetic hello", claim_for(bob))
        assert "synthetic hello" not in json.dumps(envelope)
        assert envelope["recipient"] == b.public_identity()["id"]
        assert alice.history()[0]["status"] == "pending"
        alice.mark_submitted(envelope["message_id"])
        assert alice.history()[0]["status"] == "queued"
        assert alice.pending_envelopes() == [envelope]
        received = bob.receive(envelope)
        assert received["text"] == "synthetic hello"
        receipt = bob.pending_envelopes()[0]
        assert alice.receive(receipt) is None
        assert alice.pending_envelopes() == []
        assert alice.history()[0]["status"] == "delivered"
        bob.mark_submitted(receipt["message_id"])
        assert bob.pending_envelopes() == []
        assert not bob.needs_prekey("alice")
        reply = bob.prepare_message("alice", "synthetic reply")
        assert alice.receive(reply)["text"] == "synthetic reply"
    finally:
        a.close()
        b.close()


def test_restart_preserves_prekeys_sessions_and_identical_retry(tmp_path):
    from core.e2ee import Messenger
    from core.identity import IdentityVault

    a, b, alice, bob = paired(tmp_path)
    claim = claim_for(bob)
    b.close()
    envelope = alice.prepare_message("bob", "offline synthetic", claim)
    a.close()
    a = IdentityVault.open(tmp_path / "alice.vault", "synthetic-test-passphrase-a")
    b = IdentityVault.open(tmp_path / "bob.vault", "synthetic-test-passphrase-b")
    try:
        alice, bob = Messenger(a), Messenger(b)
        assert alice.pending_envelopes() == [envelope]
        assert bob.receive(envelope)["text"] == "offline synthetic"
        receipt = bob.pending_envelopes()[0]
        b.close()
        b = IdentityVault.open(tmp_path / "bob.vault", "synthetic-test-passphrase-b")
        bob = Messenger(b)
        assert bob.pending_envelopes() == [receipt]
        assert bob.receive(envelope) is None
        assert len(bob.history()) == 1
        assert alice.receive(receipt) is None
        reply = bob.prepare_message("alice", "after restart")
        assert alice.receive(reply)["text"] == "after restart"
    finally:
        a.close()
        b.close()


def test_simultaneous_initiation_preserves_both_sessions(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        a_claim, b_claim = claim_for(alice), claim_for(bob)
        first = alice.prepare_message("bob", "from alice", b_claim)
        second = bob.prepare_message("alice", "from bob", a_claim)
        assert alice.receive(second)["text"] == "from bob"
        assert bob.receive(first)["text"] == "from alice"
        for envelope in alice.pending_envelopes():
            bob.receive(envelope)
        for envelope in bob.pending_envelopes():
            alice.receive(envelope)
        assert len(a.snapshot()["sessions"][b.public_identity()["id"]]) == 2
        assert len(b.snapshot()["sessions"][a.public_identity()["id"]]) == 2
        assert bob.receive(alice.prepare_message("bob", "next"))["text"] == "next"
    finally:
        a.close()
        b.close()


def test_out_of_order_messages_and_duplicates(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        initial = alice.prepare_message("bob", "initial", claim_for(bob))
        bob.receive(initial)
        alice.receive(bob.pending_envelopes()[0])
        first = alice.prepare_message("bob", "one")
        second = alice.prepare_message("bob", "two")
        assert bob.receive(second)["text"] == "two"
        assert bob.receive(first)["text"] == "one"
        assert bob.receive(second) is None
        assert len(bob.history()) == 3
    finally:
        a.close()
        b.close()


def test_invalid_recipient_and_revocation_do_not_advance_state(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        envelope = alice.prepare_message("bob", "synthetic", claim_for(bob))
        before = b.snapshot()
        changed = copy.deepcopy(envelope)
        changed["recipient"] = a.public_identity()["id"]
        with pytest.raises(ValueError):
            bob.receive(changed)
        assert b.snapshot() == before
        b.revoke_contact("alice", a.public_identity()["id"])
        with pytest.raises(ValueError):
            bob.receive(envelope)
        with pytest.raises(ValueError):
            bob.prepare_message("alice", "denied")
    finally:
        a.close()
        b.close()


def test_failed_commit_does_not_advance_live_crypto_state(tmp_path, monkeypatch):
    a, b, alice, bob = paired(tmp_path)
    try:
        envelope = alice.prepare_message("bob", "retry synthetic", claim_for(bob))
        original_commit = b.commit
        before = b.snapshot()

        def fail_commit(snapshot):
            raise OSError("synthetic failure")

        monkeypatch.setattr(b, "commit", fail_commit)
        with pytest.raises(OSError):
            bob.receive(envelope)
        assert b.snapshot() == before
        monkeypatch.setattr(b, "commit", original_commit)
        assert bob.receive(envelope)["text"] == "retry synthetic"
        assert bob.receive(envelope) is None
    finally:
        a.close()
        b.close()


def test_prekeys_do_not_evict_unconsumed_private_keys(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        first_claim = claim_for(bob)
        issued = bob.issue_prekeys(50)
        assert len(issued["prekeys"]) == 49
        assert bob.issue_prekeys(1)["prekeys"] == []
        assert bob.receive(alice.prepare_message("bob", "old prekey", first_claim))["text"] == "old prekey"
        assert len(bob.issue_prekeys(1)["prekeys"]) == 1
    finally:
        a.close()
        b.close()


def test_duplicate_requeues_same_receipt_after_submission(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        envelope = alice.prepare_message("bob", "synthetic", claim_for(bob))
        bob.receive(envelope)
        receipt = bob.pending_envelopes()[0]
        bob.mark_submitted(receipt["message_id"])
        assert bob.pending_envelopes() == []
        assert bob.receive(envelope) is None
        assert bob.pending_envelopes() == [receipt]
        assert len(bob.history()) == 1
        assert alice.receive(receipt) is None
        assert alice.history()[0]["status"] == "delivered"
    finally:
        a.close()
        b.close()


def test_pending_filters_and_defensive_copies(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        envelope = alice.prepare_message("bob", "synthetic", claim_for(bob))
        bob.receive(envelope)
        assert alice.pending_envelopes(receipts_only=True) == []
        assert alice.pending_envelopes(recipient=b.public_identity()["id"]) == [envelope]
        assert alice.pending_envelopes(recipient=a.public_identity()["id"]) == []
        receipt = bob.pending_envelopes(receipts_only=True)[0]
        receipt["ciphertext"] = "changed"
        assert bob.pending_envelopes()[0]["ciphertext"] != "changed"
        history = bob.history()
        history[0]["text"] = "changed"
        assert bob.history()[0]["text"] == "synthetic"
    finally:
        a.close()
        b.close()


def test_wrong_claim_and_changed_message_id_are_rejected_without_mutation(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        wrong = claim_for(alice)
        before = a.snapshot()
        with pytest.raises(ValueError):
            alice.prepare_message("bob", "synthetic", wrong)
        assert a.snapshot() == before
        envelope = alice.prepare_message("bob", "synthetic", claim_for(bob))
        before = b.snapshot()
        changed = copy.deepcopy(envelope)
        changed["message_id"] = "0" * 32
        with pytest.raises(ValueError):
            bob.receive(changed)
        assert b.snapshot() == before
        assert bob.receive(envelope)["text"] == "synthetic"
        changed = copy.deepcopy(envelope)
        changed["session_id"] = "A" * 43
        with pytest.raises(ValueError):
            bob.receive(changed)
    finally:
        a.close()
        b.close()


def test_failed_send_commit_leaves_original_session_and_outbox(tmp_path, monkeypatch):
    a, b, alice, bob = paired(tmp_path)
    try:
        first = alice.prepare_message("bob", "first", claim_for(bob))
        bob.receive(first)
        alice.receive(bob.pending_envelopes()[0])
        before = a.snapshot()
        original_commit = a.commit

        def fail_commit(snapshot):
            raise OSError("synthetic failure")

        monkeypatch.setattr(a, "commit", fail_commit)
        with pytest.raises(OSError):
            alice.prepare_message("bob", "unsaved")
        assert a.snapshot() == before
        monkeypatch.setattr(a, "commit", original_commit)
        assert bob.receive(alice.prepare_message("bob", "after failure"))["text"] == "after failure"
    finally:
        a.close()
        b.close()


def test_invalid_unicode_errors_do_not_include_text(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        private_text = "synthetic-private\ud800"
        with pytest.raises(ValueError) as caught:
            alice.prepare_message("bob", private_text)
        assert "synthetic-private" not in str(caught.value)
        assert "\\ud800" not in str(caught.value)
        assert not isinstance(caught.value, UnicodeError)
    finally:
        a.close()
        b.close()


def test_publication_bundle_survives_restart_until_explicit_ack(tmp_path):
    from core.e2ee import Messenger
    from core.identity import IdentityVault

    a, b, alice, bob = paired(tmp_path)
    try:
        original = bob.issue_prekeys(20, pool="relay:localhost:8000")
        assert bob.issue_prekeys(20, pool="relay:localhost:8000") == original
        assert b.snapshot()["prekey_count"] == 20
        b.close()
        b = IdentityVault.open(tmp_path / "bob.vault", "synthetic-test-passphrase-b")
        bob = Messenger(b)
        assert bob.issue_prekeys(20, pool="relay:localhost:8000") == original
        bob.ack_prekey_bundle("relay:localhost:8000")
        refreshed = bob.issue_prekeys(20, pool="relay:localhost:8000")
        assert refreshed != original
        assert b.snapshot()["prekey_count"] == 40
        bob.ack_prekey_bundle("relay:localhost:8000")
        bob.ack_prekey_bundle("relay:localhost:8000")
    finally:
        a.close()
        b.close()


def test_direct_bundle_is_removed_only_after_valid_inbound_commit(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        pool = "direct:" + a.public_identity()["id"]
        bundle = bob.issue_prekeys(1, pool=pool)
        claim = {"identity": bundle["identity"], "prekey": bundle["prekeys"][0]}
        envelope = alice.prepare_message("bob", "synthetic direct", claim)
        modified = dict(envelope, message_id="0" * 32)
        with pytest.raises(ValueError):
            bob.receive(modified)
        assert bob.issue_prekeys(1, pool=pool) == bundle
        assert bob.receive(envelope)["text"] == "synthetic direct"
        assert pool not in b.snapshot()["prekey_bundles"]
        assert bob.issue_prekeys(1, pool=pool) != bundle
    finally:
        a.close()
        b.close()


def test_unacknowledged_pool_does_not_consume_additional_capacity(tmp_path):
    a, b, alice, bob = paired(tmp_path)
    try:
        first = bob.issue_prekeys(50, pool="relay:localhost:8000")
        for _ in range(3):
            assert bob.issue_prekeys(50, pool="relay:localhost:8000") == first
        assert b.snapshot()["prekey_count"] == 50
        assert bob.issue_prekeys(1, pool="relay:localhost:8001")["prekeys"] == []
        assert "relay:localhost:8001" not in b.snapshot()["prekey_bundles"]
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("pool", ["", 1, "x" * 257, "relay:\nlocalhost:8000"],
                         ids=["empty", "wrong-type", "too-long", "control-character"])
def test_invalid_publication_pool_has_no_effect(tmp_path, pool):
    a, b, alice, bob = paired(tmp_path)
    try:
        before = b.snapshot()
        with pytest.raises(ValueError):
            bob.issue_prekeys(1, pool=pool)
        assert b.snapshot() == before
    finally:
        a.close()
        b.close()


def test_parallel_messenger_instances_share_vault_transaction_lock(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from core.e2ee import Messenger

    a, b, alice, bob = paired(tmp_path)
    try:
        first = alice.prepare_message("bob", "initial", claim_for(bob))
        bob.receive(first)
        alice.receive(bob.pending_envelopes()[0])
        second_alice = Messenger(a)
        with ThreadPoolExecutor(max_workers=2) as executor:
            one = executor.submit(alice.prepare_message, "bob", "parallel one")
            two = executor.submit(second_alice.prepare_message, "bob", "parallel two")
            messages = [one.result(), two.result()]
        assert {item["message_id"] for item in alice.pending_envelopes()} == {
            item["message_id"] for item in messages
        }
        received = [bob.receive(item)["text"] for item in messages]
        assert set(received) == {"parallel one", "parallel two"}
    finally:
        a.close()
        b.close()


def test_outbox_limit_preserves_existing_messages(tmp_path, monkeypatch):
    import core.e2ee as e2ee

    a, b, alice, bob = paired(tmp_path)
    try:
        monkeypatch.setattr(e2ee, "MAX_PENDING_ENVELOPES", 1)
        first = alice.prepare_message("bob", "initial", claim_for(bob))
        before = a.snapshot()
        with pytest.raises(ValueError, match="limit"):
            alice.prepare_message("bob", "full")
        assert a.snapshot() == before
        assert alice.pending_envelopes() == [first]
    finally:
        a.close()
        b.close()


def test_session_limit_preserves_existing_sessions(tmp_path, monkeypatch):
    import core.e2ee as e2ee

    a, b, alice, bob = paired(tmp_path)
    try:
        a_claim, b_claim = claim_for(alice), claim_for(bob)
        first = alice.prepare_message("bob", "initial", b_claim)
        second = bob.prepare_message("alice", "simultaneous", a_claim)
        monkeypatch.setattr(e2ee, "MAX_SESSIONS_PER_CONTACT", 1)
        before = a.snapshot()
        with pytest.raises(ValueError):
            alice.receive(second)
        assert a.snapshot() == before
        assert alice.pending_envelopes() == [first]
    finally:
        a.close()
        b.close()


def test_prekey_commit_failure_preserves_account_and_cache(tmp_path, monkeypatch):
    a, b, alice, bob = paired(tmp_path)
    try:
        before = b.snapshot()

        def fail_commit(snapshot):
            raise OSError("synthetic failure")

        monkeypatch.setattr(b, "commit", fail_commit)
        with pytest.raises(OSError):
            bob.issue_prekeys(2, pool="relay:localhost:8000")
        assert b.snapshot() == before
    finally:
        a.close()
        b.close()


def test_prekey_pool_limit_preserves_cached_bundles(tmp_path, monkeypatch):
    import core.e2ee as e2ee

    a, b, alice, bob = paired(tmp_path)
    try:
        monkeypatch.setattr(e2ee, "MAX_PREKEY_POOLS", 1)
        bundle = bob.issue_prekeys(1, pool="relay:localhost:8000")
        before = b.snapshot()
        with pytest.raises(ValueError, match="limit"):
            bob.issue_prekeys(1, pool="relay:localhost:8001")
        assert b.snapshot() == before
        assert bob.issue_prekeys(1, pool="relay:localhost:8000") == bundle
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("text", ["", "x" * 16385, "\u00e9" * 8193, None],
                         ids=["empty", "ascii-limit", "utf8-limit", "wrong-type"])
def test_invalid_text_does_not_create_a_session(tmp_path, text):
    a, b, alice, bob = paired(tmp_path)
    try:
        before = a.snapshot()
        with pytest.raises(ValueError):
            alice.prepare_message("bob", text, claim_for(bob))
        assert a.snapshot() == before
    finally:
        a.close()
        b.close()
