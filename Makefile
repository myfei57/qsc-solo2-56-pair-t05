PYTHON ?= python3

test:
	@if $(PYTHON) -c "import pytest" 2>/dev/null; then \
		PYTHONPATH=. $(PYTHON) -m pytest -q; \
	else \
		echo "未安装 pytest，使用零依赖兼容运行器 tests/../pytest.py"; \
		PYTHONPATH=. $(PYTHON) pytest.py; \
	fi

run:
	PYTHONPATH=. $(PYTHON) -m psdline --config config/psdline.json serve --host 127.0.0.1 --port 8080

demo:
	PYTHONPATH=. $(PYTHON) -m psdline --config config/psdline.json demo --fast

keys:
	PYTHONPATH=. $(PYTHON) -m psdline --config config/psdline.json keys list

deadcode:
	PYTHONPATH=. $(PYTHON) tools/deadcode.py psdline
