"""审计检索。"""

from __future__ import annotations

from .entry import AuditEntry


def by_kind(entries: list[AuditEntry], kind: str) -> list[AuditEntry]:
    """按动作类型过滤。"""

    return [entry for entry in entries if entry.kind == kind]


def by_train(entries: list[AuditEntry], train_id: str) -> list[AuditEntry]:
    """按列车过滤。"""

    return [entry for entry in entries if entry.train_id == train_id]


def kinds(entries: list[AuditEntry]) -> list[str]:
    """返回出现过的动作类型（排序）。"""

    return sorted({entry.kind for entry in entries})


def count_by_kind(entries: list[AuditEntry], kind: str) -> int:
    """统计某动作类型的条数。"""

    return len(by_kind(entries, kind))


VERDICT_KINDS = frozenset(
    {
        "command_verified",
        "command_rejected",
        "command_held",
        "command_rolled_back",
        "command_executed",
    }
)


def by_auth(entries: list[AuditEntry], auth_id: str) -> list[AuditEntry]:
    """按验签凭据过滤：重建一条指令"验签 → 联锁/门控 → 执行/回滚"的链路。"""

    return [entry for entry in entries if entry.detail.get("auth_id") == auth_id]


def verification_verdicts(entries: list[AuditEntry]) -> list[AuditEntry]:
    """只看指令级验签结论（通过/拒绝/挂起/回滚/执行）。"""

    return [entry for entry in entries if entry.kind in VERDICT_KINDS]
