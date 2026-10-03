"""原子 JSON 文档存储。

每个文档一个 ``<doc_id>.json`` 文件，``doc_id`` 可以带 ``/`` 变成子目录（例如
``station/ST1/layout``）。写入时先写同目录下的临时文件再 ``os.replace`` 原子
替换，保证中途掉电不会留下半截文档；读取时容忍文件不存在（返回 ``None``），由
调用方决定是否使用默认值。
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from typing import Any, Iterator

from ..errors import StorageError

# 回滚条目：``(doc_id, prior)``，``prior is None`` 表示事务前文件不存在。
_UndoEntry = tuple[str, Any]


class JsonStore:
    """目录形式的 JSON 文档存储。"""

    def __init__(self, root: str) -> None:
        self._root = os.path.abspath(root)
        self._lock = threading.RLock()
        self._txn_stack: threading.local = threading.local()
        os.makedirs(self._root, exist_ok=True)

    @property
    def root(self) -> str:
        return self._root

    def _frames(self) -> list[list[_UndoEntry]]:
        """返回当前线程的事务帧栈（无事务时为空栈）。"""

        stack = getattr(self._txn_stack, "frames", None)
        if stack is None:
            stack = []
            self._txn_stack.frames = stack
        return stack

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """开一个线程内事务：块内异常把本次全部写入逆序恢复到事务前。

        嵌套事务只有最外层负责提交/回滚；内层异常向上抛出，由外层统一恢复。
        只覆盖本文档存储的 ``write`` / ``remove``；JSONL 流水（审计、nonce
        台账）只追加不回滚——nonce 已消费就不能再被同一条指令重放。
        """

        frames = self._frames()
        frames.append([])
        try:
            yield
        except BaseException:
            frame = frames.pop()
            # 内层帧把自己的逆序操作并入外层，由外层一并恢复；最外层直接恢复。
            if frames:
                frames[-1].extend(reversed(frame))
            else:
                for doc_id, prior in reversed(frame):
                    self._restore(doc_id, prior)
            raise
        else:
            frame = frames.pop()
            if frames:
                # 内层提交：保留首次写入前的快照，顺序并入外层逆序表。
                frames[-1].extend(reversed(frame))

    def _restore(self, doc_id: str, prior: Any) -> None:
        """把文档恢复成事务前的样子（``None`` 表示删掉）。"""

        with self._lock:
            target = self.path_of(doc_id)
            directory = os.path.dirname(target)
            try:
                if prior is None:
                    if os.path.isfile(target):
                        os.remove(target)
                else:
                    os.makedirs(directory, exist_ok=True)
                    handle = tempfile.NamedTemporaryFile(
                        "w",
                        encoding="utf-8",
                        dir=directory,
                        prefix=".rollback.",
                        suffix=".tmp",
                        delete=False,
                    )
                    with handle:
                        json.dump(prior, handle, ensure_ascii=False, indent=2)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(handle.name, target)
            except OSError as error:
                raise StorageError(f"回滚文档 {doc_id} 失败: {error}", component="store") from error

    def path_of(self, doc_id: str) -> str:
        """返回某文档对应的文件路径。"""

        relative = doc_id.replace("\\", "/").strip("/")
        if not relative:
            raise StorageError("文档标识不能为空", component="store")
        return os.path.join(self._root, *relative.split("/")) + ".json"

    def exists(self, doc_id: str) -> bool:
        """文档文件是否存在。"""

        return os.path.isfile(self.path_of(doc_id))

    def write(self, doc_id: str, payload: Any) -> str:
        """原子写入一个文档，返回最终文件路径。"""

        target = self.path_of(doc_id)
        directory = os.path.dirname(target)
        frames = self._frames()
        with self._lock:
            if frames and not any(entry[0] == doc_id for frame in frames for entry in frame):
                # 只记事务开始后的第一份快照，回滚时才能恢复成事务前的样子。
                frames[-1].append((doc_id, self.read(doc_id)))
            try:
                os.makedirs(directory, exist_ok=True)
                handle = tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=directory,
                    prefix=".write.",
                    suffix=".tmp",
                    delete=False,
                )
                with handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(handle.name, target)
            except OSError as error:
                raise StorageError(f"写入文档 {doc_id} 失败: {error}", component="store") from error
        return target

    def read(self, doc_id: str) -> Any | None:
        """读取一个文档，不存在时返回 ``None``。"""

        target = self.path_of(doc_id)
        with self._lock:
            if not os.path.isfile(target):
                return None
            try:
                with open(target, "r", encoding="utf-8") as handle:
                    return json.load(handle)
            except (OSError, json.JSONDecodeError) as error:
                raise StorageError(f"读取文档 {doc_id} 失败: {error}", component="store") from error

    def remove(self, doc_id: str) -> bool:
        """删除一个文档，返回是否真的删掉了文件。"""

        target = self.path_of(doc_id)
        frames = self._frames()
        with self._lock:
            if not os.path.isfile(target):
                return False
            if frames and not any(entry[0] == doc_id for frame in frames for entry in frame):
                frames[-1].append((doc_id, self.read(doc_id)))
            os.remove(target)
            return True

    def list_ids(self) -> list[str]:
        """列出全部文档标识（相对根目录、去扩展名、排序后）。"""

        with self._lock:
            found: list[str] = []
            for base, _dirs, files in os.walk(self._root):
                for name in files:
                    if not name.endswith(".json"):
                        continue
                    full = os.path.join(base, name)
                    relative = os.path.relpath(full, self._root)
                    found.append(relative[: -len(".json")].replace(os.sep, "/"))
        return sorted(found)
