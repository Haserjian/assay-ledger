"""Idempotency key parsing for the optional ledger REST wrapper."""
from __future__ import annotations

import re
from dataclasses import dataclass


REPO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class IdempotencyKey:
    owner: str
    repo: str
    commit_sha: str
    action_hash: str

    @property
    def raw(self) -> str:
        return f"{self.owner}:{self.repo}:{self.commit_sha}:{self.action_hash}"


def parse_idempotency_key(value: str) -> IdempotencyKey:
    """Parse owner:repo:commit_sha:action_hash.

    The action hash is a SHA-256 hex digest of the canonical action intent.
    """
    parts = value.split(":")
    if len(parts) != 4:
        raise ValueError("Idempotency-Key must have 4 colon-separated segments")

    owner, repo, commit_sha, action_hash = parts
    if not owner or not REPO_SEGMENT_RE.match(owner):
        raise ValueError("Idempotency-Key owner segment is invalid")
    if not repo or not REPO_SEGMENT_RE.match(repo):
        raise ValueError("Idempotency-Key repo segment is invalid")
    if not HEX40_RE.match(commit_sha):
        raise ValueError("Idempotency-Key commit_sha must be 40 hex characters")
    if not HEX64_RE.match(action_hash):
        raise ValueError("Idempotency-Key action_hash must be 64 hex characters")

    return IdempotencyKey(
        owner=owner,
        repo=repo,
        commit_sha=commit_sha.lower(),
        action_hash=action_hash.lower(),
    )
