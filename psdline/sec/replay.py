"""重放防护登记簿。

每条验签通过的指令都会把 ``指令标识 → (随机数, 失效时刻)`` 登记进
``sec/replay`` 文档。登记与判定在同一把锁里完成（check-and-claim 原子化），
并发提交同一信封时只有一条能认领成功，其余一律按重放拒绝。

登记簿随指令失效时刻惰性清理：指令一旦过期，即使攻击者重放也会在"过期"检查
处被拦下，因此登记条目只需保留到指令失效为止。登记簿落盘，服务重启后重启前
认领过的指令依然无法重放。
"""

from __future__ import annotations

import threading

from ..store import JsonStore

_DOC_ID = "sec/replay"


class ReplayGuard:
    """落盘的已认领指令登记簿。"""

    def __init__(self, store: JsonStore) -> None:
        self._store = store
        self._lock = threading.RLock()

    def _load(self) -> dict:
        raw = self._store.read(_DOC_ID)
        if isinstance(raw, dict) and isinstance(raw.get("commands"), dict):
            return dict(raw["commands"])
        return {}

    def _save(self, commands: dict) -> None:
        self._store.write(_DOC_ID, {"commands": commands})

    def claim(self, command_id: str, nonce: str, expires_at: float, now: float) -> bool:
        """认领一条指令：已登记（未过期）则判定重放，返回 ``False``。"""

        with self._lock:
            commands = self._load()
            commands = {
                cid: entry
                for cid, entry in commands.items()
                if float(entry.get("expires_at", 0.0)) > now
            }
            if command_id in commands:
                self._save(commands)
                return False
            commands[command_id] = {"nonce": nonce, "expires_at": expires_at}
            self._save(commands)
            return True

    def release(self, command_id: str) -> bool:
        """撤销认领（仅用于执行失败的回滚路径，让发送方能原样重试）。"""

        with self._lock:
            commands = self._load()
            if command_id not in commands:
                return False
            del commands[command_id]
            self._save(commands)
            return True

    def size(self) -> int:
        """返回当前登记中的指令条数。"""

        with self._lock:
            return len(self._load())
