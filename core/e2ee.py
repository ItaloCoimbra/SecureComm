"""Persistent, contact-pinned Olm conversations, independent of their transport.

Only detached account/session objects are advanced. Ciphertext leaves this layer
after the matching state and retry envelope have committed to the encrypted vault.
"""

import base64
import copy
import hashlib
import json
import re
import time
import uuid

from vodozemac import Account, AnyOlmMessage, Curve25519PublicKey, Session

from core.identity import VaultError

from core.protocol import (
    MAX_TEXT_BYTES,
    canonical_bytes,
    prekey_signing_bytes,
    validate_bundle,
    validate_claim,
    validate_envelope,
)


MAX_SESSIONS_PER_CONTACT = 64
MAX_PENDING_ENVELOPES = 2000
MAX_PREKEY_POOLS = 64


class CapacityError(VaultError):
    """Local capacity is exhausted; a remote message must be retained for retry."""


class Messenger:
    """Conversation operations serialized with the vault's transaction lock."""

    def __init__(self, vault):
        self.vault = vault

    @staticmethod
    def _pickle_key(state):
        return base64.b64decode(state["pickle_key"], validate=True)

    @classmethod
    def _account(cls, state):
        return Account.from_pickle(state["account"], cls._pickle_key(state))

    @staticmethod
    def _validate_text(text):
        try:
            valid = isinstance(text, str) and bool(text) and len(text.encode("utf-8")) <= MAX_TEXT_BYTES
        except UnicodeError:
            valid = False
        if not valid:
            raise ValueError("Message text must be nonempty and within the size limit")

    @staticmethod
    def _validate_pool(pool):
        if not isinstance(pool, str) or not 1 <= len(pool) <= 256 or not all(
            33 <= ord(character) <= 126 for character in pool
        ):
            raise ValueError("Invalid prekey publication pool")

    def issue_prekeys(self, count=20, *, pool=None):
        """Commit new private prekeys before exposing their signed public half.

        Published private keys are retained until successfully consumed. Capacity
        exhaustion returns an empty bundle instead of evicting keys still in use.
        A named pool caches the identical bundle until publication is acknowledged,
        so an interrupted relay request can be retried without wasting capacity.
        """
        if type(count) is not int or not 1 <= count <= 50:
            raise ValueError("Prekey count must be between 1 and 50")
        if pool is not None:
            self._validate_pool(pool)
        with self.vault.transaction_lock:
            state = self.vault.snapshot()
            if pool is not None:
                cached = state["prekey_bundles"].get(pool)
                if cached is not None:
                    return copy.deepcopy(cached)
                if len(state["prekey_bundles"]) >= MAX_PREKEY_POOLS:
                    raise ValueError("Pending prekey publication limit reached")
            account = self._account(state)
            identity = self.vault.public_identity()
            capacity = max(0, account.max_number_of_one_time_keys - state["prekey_count"])
            generated = min(count, capacity)
            if generated:
                account.generate_one_time_keys(generated)
            prekeys = []
            for key_id, key in account.one_time_keys.items():
                public = key.to_base64()
                signature = account.sign(
                    prekey_signing_bytes(identity["id"], key_id, public)
                ).to_base64()
                prekeys.append({"id": key_id, "key": public, "signature": signature})
            bundle = {"identity": identity, "prekeys": prekeys}
            validate_bundle(bundle)
            if generated:
                account.mark_keys_as_published()
                state["account"] = account.pickle(self._pickle_key(state))
                state["prekey_count"] += generated
                if pool is not None:
                    state["prekey_bundles"][pool] = bundle
                self.vault.commit(state)
            return copy.deepcopy(bundle)

    def ack_prekey_bundle(self, pool):
        """Forget a cached public bundle after its relay accepted publication."""
        self._validate_pool(pool)
        with self.vault.transaction_lock:
            state = self.vault.snapshot()
            if pool in state["prekey_bundles"]:
                del state["prekey_bundles"][pool]
                self.vault.commit(state)

    def needs_prekey(self, alias):
        with self.vault.transaction_lock:
            contact = self.vault.get_contact(alias)
            return not bool(self.vault.snapshot()["sessions"].get(contact["identity"]["id"]))

    @staticmethod
    def _check_outbox_space(state, kind="text"):
        # Texts cannot consume the bounded capacity needed for delivery receipts.
        if sum(entry["kind"] == kind for entry in state["outbox"].values()) >= MAX_PENDING_ENVELOPES:
            raise CapacityError("Pending message limit reached; synchronize first")

    @staticmethod
    def _payload(sender, recipient, kind, **fields):
        return {
            "v": 1,
            "sender": sender,
            "recipient": recipient,
            "message_id": uuid.uuid4().hex,
            "kind": kind,
            "timestamp": int(time.time()),
            **fields,
        }

    def _encrypt(self, state, session, payload):
        self._check_outbox_space(state, payload["kind"])
        encrypted = session.encrypt(canonical_bytes(payload))
        message_type, ciphertext = encrypted.to_parts()
        envelope = {
            "v": 1,
            "sender": payload["sender"],
            "recipient": payload["recipient"],
            "message_id": payload["message_id"],
            "session_id": session.session_id,
            "message_type": message_type,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        validate_envelope(envelope)
        state["outbox"][payload["message_id"]] = {
            "envelope": envelope,
            "kind": payload["kind"],
            "status": "pending",
        }
        state["sessions"].setdefault(payload["recipient"], {})[session.session_id] = (
            session.pickle(self._pickle_key(state))
        )
        return envelope

    def prepare_message(self, alias, text, claim=None):
        """Persist one ciphertext and its advanced session before returning it."""
        self._validate_text(text)
        with self.vault.transaction_lock:
            contact = self.vault.get_contact(alias)
            peer = contact["identity"]
            state = self.vault.snapshot()
            sessions = state["sessions"].get(peer["id"], {})
            if claim is not None:
                claim = validate_claim(claim, expected_identity=peer)
            if sessions:
                # Stable across vault JSON serialization and simultaneous starts.
                session = Session.from_pickle(sessions[min(sessions)], self._pickle_key(state))
            else:
                if claim is None:
                    raise ValueError("A signed contact prekey is required")
                account = self._account(state)
                try:
                    session = account.create_outbound_session(
                        Curve25519PublicKey.from_base64(peer["curve25519"]),
                        Curve25519PublicKey.from_base64(claim["prekey"]["key"]),
                    )
                except Exception:
                    raise ValueError("Unable to establish conversation session") from None
            payload = self._payload(self.vault.public_identity()["id"], peer["id"], "text", text=text)
            envelope = self._encrypt(state, session, payload)
            state["history"].append({
                **payload,
                "alias": alias,
                "direction": "outgoing",
                "status": "pending",
            })
            self.vault.commit(state)
            return copy.deepcopy(envelope)

    @classmethod
    def _decode_payload(cls, plaintext, envelope):
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ValueError("Invalid authenticated message") from None
        if not isinstance(payload, dict) or canonical_bytes(payload) != plaintext:
            raise ValueError("Invalid authenticated message")
        common = {"v", "sender", "recipient", "message_id", "kind", "timestamp"}
        kind = payload.get("kind")
        required = common | ({"text"} if kind == "text" else {"acknowledged_id"})
        if kind not in ("text", "receipt") or set(payload) != required:
            raise ValueError("Invalid authenticated message fields")
        for key in ("v", "sender", "recipient", "message_id"):
            if payload.get(key) != envelope[key]:
                raise ValueError("Authenticated message binding mismatch")
        if type(payload["v"]) is not int or type(payload["timestamp"]) is not int:
            raise ValueError("Invalid authenticated message version or timestamp")
        if not 0 <= payload["timestamp"] < 2**63:
            raise ValueError("Invalid authenticated message timestamp")
        if kind == "text":
            cls._validate_text(payload["text"])
        elif not isinstance(payload["acknowledged_id"], str) or not re.fullmatch(
            r"[0-9a-f]{32}", payload["acknowledged_id"]
        ):
            raise ValueError("Invalid delivery acknowledgement")
        return payload

    def _decrypt(self, state, peer, envelope):
        try:
            message = AnyOlmMessage.from_parts(
                envelope["message_type"], base64.b64decode(envelope["ciphertext"], validate=True)
            )
            sessions = state["sessions"].get(peer["id"], {})
            stored = sessions.get(envelope["session_id"])
            if stored is not None:
                session = Session.from_pickle(stored, self._pickle_key(state))
                if session.session_id != envelope["session_id"]:
                    raise ValueError("Session binding mismatch")
                if envelope["message_type"] == 0 and not session.session_matches(message.to_pre_key()):
                    raise ValueError("Session binding mismatch")
                plaintext = session.decrypt(message)
                return session, plaintext, None
            if envelope["message_type"] != 0 or len(sessions) >= MAX_SESSIONS_PER_CONTACT:
                raise ValueError("Unknown conversation session or session limit reached")
            if message.to_pre_key().session_id() != envelope["session_id"]:
                raise ValueError("Session binding mismatch")
            account = self._account(state)
            session, plaintext = account.create_inbound_session(
                Curve25519PublicKey.from_base64(peer["curve25519"]), message.to_pre_key()
            )
            if session.session_id != envelope["session_id"]:
                raise ValueError("Session binding mismatch")
            return session, plaintext, account
        except Exception:
            # Binding errors and library errors must not expose message material.
            raise ValueError("Unable to authenticate conversation message") from None

    def receive(self, envelope):
        """Authenticate, deduplicate, and commit a message and encrypted receipt.

        Received texts are returned once. Receipts and exact retries return None.
        A retry restores the exact previous receipt, without advancing any ratchet.
        """
        envelope = validate_envelope(envelope)
        with self.vault.transaction_lock:
            own_id = self.vault.public_identity()["id"]
            if envelope["recipient"] != own_id:
                raise ValueError("Message is addressed to another identity")
            contact = self.vault.require_contact_id(envelope["sender"])
            state = self.vault.snapshot()
            digest = hashlib.sha256(canonical_bytes(envelope)).hexdigest()
            seen = state["seen"].get(envelope["message_id"])
            if seen is not None:
                if seen["digest"] != digest or seen["sender"] != envelope["sender"]:
                    raise ValueError("Conflicting message identifier")
                receipt = seen.get("receipt_envelope")
                if receipt is not None and receipt["message_id"] not in state["outbox"]:
                    self._check_outbox_space(state, "receipt")
                    state["outbox"][receipt["message_id"]] = {
                        "envelope": receipt, "kind": "receipt", "status": "pending"
                    }
                    self.vault.commit(state)
                return None
            session, plaintext, account = self._decrypt(state, contact["identity"], envelope)
            payload = self._decode_payload(plaintext, envelope)
            if any(row["message_id"] == payload["message_id"] for row in state["history"]):
                raise ValueError("Conflicting message identifier")
            record = {"digest": digest, "sender": envelope["sender"]}
            event = None
            if payload["kind"] == "text":
                event = {**payload, "alias": contact["alias"], "direction": "incoming", "status": "received"}
                receipt = self._payload(own_id, envelope["sender"], "receipt", acknowledged_id=payload["message_id"])
                record["receipt_envelope"] = self._encrypt(state, session, receipt)
                state["history"].append(event)
            else:
                acknowledged = payload["acknowledged_id"]
                sent = next((row for row in state["history"] if row["message_id"] == acknowledged
                             and row["direction"] == "outgoing" and row["recipient"] == envelope["sender"]), None)
                if sent is None:
                    raise ValueError("Receipt does not match a sent message")
                sent["status"] = "delivered"
                state["outbox"].pop(acknowledged, None)
                state["sessions"].setdefault(envelope["sender"], {})[session.session_id] = (
                    session.pickle(self._pickle_key(state))
                )
            if account is not None:
                state["account"] = account.pickle(self._pickle_key(state))
                state["prekey_count"] = max(0, state["prekey_count"] - 1)
                state["prekey_bundles"].pop("direct:" + envelope["sender"], None)
            state["seen"][envelope["message_id"]] = record
            self.vault.commit(state)
            return copy.deepcopy(event)

    def pending_envelopes(self, recipient=None, receipts_only=False):
        with self.vault.transaction_lock:
            return [entry["envelope"] for entry in self.vault.snapshot()["outbox"].values()
                    if (recipient is None or entry["envelope"]["recipient"] == recipient)
                    and (not receipts_only or entry["kind"] == "receipt")]

    def mark_submitted(self, message_id):
        """Relay acceptance queues text; only authenticated receipts deliver it."""
        with self.vault.transaction_lock:
            state = self.vault.snapshot()
            entry = state["outbox"].get(message_id)
            if entry is None:
                return
            if entry["kind"] == "receipt":
                del state["outbox"][message_id]
            else:
                entry["status"] = "queued"
                for row in state["history"]:
                    if row["message_id"] == message_id:
                        row["status"] = "queued"
                        break
            self.vault.commit(state)

    def history(self):
        with self.vault.transaction_lock:
            return self.vault.snapshot()["history"]
