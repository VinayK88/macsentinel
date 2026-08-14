from __future__ import annotations

import runpy
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class _Container:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def metric(self, *args, **kwargs):
        return None


def _fake_streamlit() -> types.ModuleType:
    module = types.ModuleType("streamlit")
    module.sidebar = _Container()

    def sink(*args, **kwargs):
        return None

    def cache_data(function):
        return function

    def columns(count):
        return [_Container() for _ in range(count)]

    def tabs(names):
        return [_Container() for _ in names]

    def multiselect(label, options, default=None, **kwargs):
        return list(default if default is not None else options)

    def selectbox(label, options, **kwargs):
        return next(iter(options))

    for name in [
        "set_page_config",
        "markdown",
        "title",
        "caption",
        "header",
        "divider",
        "subheader",
        "write",
        "info",
        "code",
        "image",
        "table",
        "warning",
        "error",
    ]:
        setattr(module, name, sink)
    module.cache_data = cache_data
    module.columns = columns
    module.tabs = tabs
    module.multiselect = multiselect
    module.selectbox = selectbox
    module.file_uploader = lambda *args, **kwargs: None
    module.slider = lambda *args, **kwargs: 0.50
    module.stop = lambda: (_ for _ in ()).throw(RuntimeError("unexpected st.stop"))
    return module


class MacSentinelAppSmokeTests(unittest.TestCase):
    def test_default_dashboard_render_path(self):
        original = sys.modules.get("streamlit")
        sys.modules["streamlit"] = _fake_streamlit()
        try:
            runpy.run_path(str(ROOT / "app.py"), run_name="__main__")
        finally:
            if original is None:
                sys.modules.pop("streamlit", None)
            else:
                sys.modules["streamlit"] = original


if __name__ == "__main__":
    unittest.main()
