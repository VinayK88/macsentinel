"""Execute MacSentinel notebooks and embed bounded text and PNG outputs."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import traceback
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NOTEBOOK_DIR = ROOT / "notebooks"
REQUIRED_SECTIONS = (
    "## tl;dr",
    "## Goal",
    "## Setup",
    "## Steps",
    "## Visual Insights & ML Extension",
    "## Checks",
    "## Next Steps",
)


def source_text(cell: dict) -> str:
    source = cell.get("source", "")
    return "".join(source) if isinstance(source, list) else str(source)


def validate_structure(path: Path, payload: dict) -> None:
    if payload.get("nbformat") != 4:
        raise ValueError(f"{path.name}: expected nbformat 4")
    cells = payload.get("cells", [])
    markdown_text = "\n".join(source_text(cell) for cell in cells if cell.get("cell_type") == "markdown")
    missing = [section for section in REQUIRED_SECTIONS if section not in markdown_text]
    if missing:
        raise ValueError(f"{path.name}: missing sections {missing}")
    if len([cell for cell in cells if cell.get("cell_type") == "code"]) < 6:
        raise ValueError(f"{path.name}: expected at least six code cells")


def embed_figures(cell: dict, namespace: dict) -> int:
    figures = namespace.get("FIGURES", [])
    count = 0
    while figures:
        image = figures.pop(0)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG", optimize=True)
        cell["outputs"].append(
            {
                "data": {
                    "image/png": base64.b64encode(buffer.getvalue()).decode("ascii"),
                    "text/plain": ["<MacSentinel visualization: embedded validation render>"],
                },
                "metadata": {},
                "output_type": "display_data",
            }
        )
        count += 1
    return count


def execute_notebook(path: Path) -> tuple[int, int, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    validate_structure(path, payload)
    namespace = {"__name__": "__main__"}
    code_count = 0
    output_chars = 0
    figure_count = 0
    for cell_index, cell in enumerate(payload["cells"], start=1):
        if cell.get("cell_type") != "code":
            continue
        code_count += 1
        cell["execution_count"] = code_count
        cell["outputs"] = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exec(compile(source_text(cell), f"{path.name}:cell-{cell_index}", "exec"), namespace)
        except Exception as exc:
            captured = stdout.getvalue() + stderr.getvalue()
            if captured:
                cell["outputs"].append({"name": "stdout", "output_type": "stream", "text": captured.splitlines(keepends=True)})
            cell["outputs"].append(
                {
                    "ename": type(exc).__name__,
                    "evalue": str(exc),
                    "output_type": "error",
                    "traceback": traceback.format_exc().splitlines(),
                }
            )
            path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            raise RuntimeError(f"{path.name}: execution failed in code cell {cell_index}") from exc
        captured = stdout.getvalue() + stderr.getvalue()
        output_chars += len(captured)
        if captured:
            cell["outputs"].append({"name": "stdout", "output_type": "stream", "text": captured.splitlines(keepends=True)})
        figure_count += embed_figures(cell, namespace)
    path.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return code_count, output_chars, figure_count


def main() -> None:
    paths = sorted(NOTEBOOK_DIR.glob("*.ipynb"))
    if len(paths) != 6:
        raise ValueError(f"Expected six MacSentinel notebooks, found {len(paths)}")
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    total_figures = 0
    for path in paths:
        code_cells, output_chars, figures = execute_notebook(path)
        total_figures += figures
        print(f"validated {path.name}: {code_cells} code cells, {figures} figures, {output_chars} output characters")
    print(f"validated {len(paths)} notebooks with {total_figures} embedded figures")


if __name__ == "__main__":
    main()
