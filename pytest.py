"""零依赖的极简 pytest 兼容层（仅本仓库验证期使用）。

生产运行期仍然只有 Python 标准库；开发机装有真 pytest 时优先用真的，没装时
本垫片提供测试用到的最小能力：``raises``、``fixture``、``tmp_path``/
``clock``/``platform``/``online`` 夹具注入与 ``test_*`` 函数收集执行。
不追求与 pytest 完全一致，只保证本仓库 ``tests/`` 能直接 ``python -m pytest``
跑起来（Make 的 ``test`` 目标也走这里）。

夹具按依赖递归构造，同一次测试内同名夹具共享同一个实例（因此
``platform(tmp_path, clock)`` 用的时钟与测试参数里的 ``clock`` 是同一个）。
"""

from __future__ import annotations

import contextlib
import importlib.util
import inspect
import pathlib
import sys
import tempfile
import traceback
import types

FIXTURES: dict[str, callable] = {}


def fixture(*args, **kwargs):
    def wrap(func):
        FIXTURES[func.__name__] = func
        return func

    if args and callable(args[0]):
        return wrap(args[0])
    return wrap


class _Raises:
    def __init__(self, expected, *, match: str | None = None) -> None:
        self.expected = expected
        self.match = match
        self.value: Exception | None = None

    def __enter__(self) -> "_Raises":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None:
            raise AssertionError(f"应当抛出 {self.expected!r}，但没有异常")
        if not issubclass(exc_type, self.expected):
            return False
        self.value = exc
        if self.match and self.match not in str(exc):
            raise AssertionError(f"异常信息 {str(exc)!r} 不匹配 {self.match!r}")
        return True


def raises(expected, *, match: str | None = None):
    return _Raises(expected, match=match)


def _load_conftest(tests_dir: pathlib.Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("conftest", tests_dir / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["conftest"] = module
    spec.loader.exec_module(module)
    return module


class _Scope:
    """一次测试调用内的夹具缓存与临时目录清理。"""

    def __init__(self, prefix: str) -> None:
        self._values: dict[str, object] = {}
        self._temps: list[tempfile.TemporaryDirectory] = []
        self._prefix = prefix

    def get(self, name: str) -> object:
        if name in self._values:
            return self._values[name]
        if name == "tmp_path":
            tmp = tempfile.TemporaryDirectory(prefix=self._prefix)
            self._temps.append(tmp)
            value = pathlib.Path(tmp.name)
        elif name in FIXTURES:
            func = FIXTURES[name]
            kwargs = {pname: self.get(pname) for pname in inspect.signature(func).parameters}
            value = func(**kwargs)
        else:
            raise AssertionError(f"未知夹具: {name}")
        self._values[name] = value
        return value

    def cleanup(self) -> None:
        for tmp in self._temps:
            with contextlib.suppress(OSError):
                tmp.cleanup()


def main(argv: list[str] | None = None) -> int:
    own = pathlib.Path(__file__).resolve()
    tests_dir = own.parent / "tests" if (own.parent / "tests" / "conftest.py").is_file() else own.parent
    root = tests_dir.parent
    sys.path.insert(0, str(root))
    conftest = _load_conftest(tests_dir)
    for name in ("tmp_path", "clock", "platform", "online", "signer", "signed_post"):
        func = getattr(conftest, name, None)
        if callable(func):
            FIXTURES.setdefault(name, func)

    files = sorted(tests_dir.glob("test_*.py"))
    passed = failed = 0
    failures: list[str] = []
    for path in files:
        module_name = f"tests.{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        for name, func in vars(module).items():
            if not name.startswith("test_") or not callable(func):
                continue
            scope = _Scope(f"psdline-{path.stem}-")
            try:
                kwargs = {
                    pname: scope.get(pname)
                    for pname in inspect.signature(func).parameters
                }
                func(**kwargs)
                passed += 1
                print(".", end="", flush=True)
            except Exception:  # noqa: BLE001 - 测试失败要继续跑完
                failed += 1
                failures.append(f"{path.name}::{name}\n{traceback.format_exc()}")
                print("F", end="", flush=True)
            finally:
                scope.cleanup()
    print()
    for item in failures:
        print("=" * 70)
        print(item)
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
