"""Dependency-light, GitHub-friendly security visualizations using Pillow."""

from __future__ import annotations

import io
import math
from collections import defaultdict
from typing import Iterable, Sequence

import numpy as np
import pandas as pd
from PIL import Image, ImageDraw, ImageFont


WIDTH = 1200
HEIGHT = 700
WHITE = "#FFFFFF"
PAPER = "#F7F8FA"
INK = "#182230"
MUTED = "#667085"
GRID = "#DDE2E8"
ORANGE = "#F97316"
ORANGE_LIGHT = "#FED7AA"
CRIMSON = "#D92D20"
CRIMSON_LIGHT = "#FECACA"
BLUE = "#2563EB"
BLUE_LIGHT = "#BFDBFE"
GOLD = "#EAAA08"


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    names = [
        "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for name in names:
        try:
            return ImageFont.truetype(name, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _canvas(title: str, subtitle: str = "", width: int = WIDTH, height: int = HEIGHT):
    image = Image.new("RGB", (width, height), WHITE)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((18, 18, width - 18, height - 18), radius=24, fill=PAPER, outline=GRID, width=2)
    draw.text((58, 42), title, font=_font(32, True), fill=INK)
    if subtitle:
        draw.text((58, 86), subtitle, font=_font(17), fill=MUTED)
    draw.line((58, 126, width - 58, 126), fill=GRID, width=2)
    return image, draw


def _format_value(value: float) -> str:
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.1f}K"
    if abs(value) < 1 and value != 0:
        return f"{value:.2f}"
    return f"{value:.0f}"


def to_png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def bar_chart(
    labels: Sequence[str],
    values: Sequence[float],
    title: str,
    subtitle: str = "",
    color: str = ORANGE,
    benchmark: float | None = None,
) -> Image.Image:
    image, draw = _canvas(title, subtitle)
    labels = [str(label).replace("_", " ") for label in labels]
    values = np.asarray(values, dtype=float)
    left, top, right, bottom = 260, 160, 1120, 630
    max_value = max(float(values.max(initial=0)), float(benchmark or 0), 1.0)
    row_height = (bottom - top) / max(len(labels), 1)
    for grid_fraction in np.linspace(0, 1, 6):
        x = left + grid_fraction * (right - left)
        draw.line((x, top, x, bottom), fill=GRID, width=1)
        draw.text((x - 12, bottom + 8), _format_value(max_value * grid_fraction), font=_font(14), fill=MUTED)
    if benchmark is not None:
        benchmark_x = left + benchmark / max_value * (right - left)
        draw.line((benchmark_x, top, benchmark_x, bottom), fill=INK, width=2)
        draw.text((benchmark_x + 5, top - 20), f"reference {_format_value(benchmark)}", font=_font(13), fill=INK)
    for index, (label, value) in enumerate(zip(labels, values)):
        y0 = top + index * row_height + row_height * 0.20
        y1 = top + (index + 1) * row_height - row_height * 0.20
        width = value / max_value * (right - left)
        fill = color if index != int(values.argmax()) else CRIMSON
        draw.rounded_rectangle((left, y0, left + width, y1), radius=8, fill=fill, outline=INK, width=1)
        draw.text((58, y0 + 4), label[:24], font=_font(16), fill=INK)
        draw.text((min(left + width + 10, right - 55), y0 + 4), _format_value(value), font=_font(15, True), fill=INK)
    return image


def line_chart(
    x_values: Sequence,
    series: dict[str, Sequence[float]],
    title: str,
    subtitle: str = "",
    y_label: str = "value",
) -> Image.Image:
    image, draw = _canvas(title, subtitle)
    left, top, right, bottom = 105, 165, 1120, 605
    all_values = np.concatenate([np.asarray(values, dtype=float) for values in series.values()])
    y_min = min(0.0, float(all_values.min(initial=0)))
    y_max = max(1.0, float(all_values.max(initial=1)))
    palette = [ORANGE, BLUE, CRIMSON, GOLD]
    for fraction in np.linspace(0, 1, 6):
        y = bottom - fraction * (bottom - top)
        value = y_min + fraction * (y_max - y_min)
        draw.line((left, y, right, y), fill=GRID, width=1)
        draw.text((42, y - 8), _format_value(value), font=_font(13), fill=MUTED)
    count = max(len(x_values), 2)
    for series_index, (name, values) in enumerate(series.items()):
        values = np.asarray(values, dtype=float)
        points = []
        for index, value in enumerate(values):
            x = left + index / max(count - 1, 1) * (right - left)
            y = bottom - (value - y_min) / max(y_max - y_min, 1e-9) * (bottom - top)
            points.append((x, y))
        color = palette[series_index % len(palette)]
        if len(points) > 1:
            draw.line(points, fill=color, width=4)
        for x, y in points:
            draw.ellipse((x - 5, y - 5, x + 5, y + 5), fill=WHITE, outline=color, width=3)
        legend_x = 760 + series_index * 105
        draw.line((legend_x, 112, legend_x + 28, 112), fill=color, width=4)
        draw.text((legend_x + 35, 102), name, font=_font(14), fill=INK)
    if x_values:
        tick_indices = np.linspace(0, len(x_values) - 1, min(7, len(x_values))).astype(int)
        for index in sorted(set(tick_indices.tolist())):
            x = left + index / max(count - 1, 1) * (right - left)
            draw.text((x - 20, bottom + 12), str(x_values[index])[:10], font=_font(12), fill=MUTED)
    draw.text((38, 140), y_label, font=_font(13, True), fill=MUTED)
    return image


def histogram(
    values_by_group: dict[str, Sequence[float]],
    title: str,
    subtitle: str = "",
    bins: int = 16,
) -> Image.Image:
    image, draw = _canvas(title, subtitle)
    left, top, right, bottom = 105, 165, 1120, 605
    all_values = np.concatenate([np.asarray(values, dtype=float) for values in values_by_group.values()])
    minimum, maximum = float(all_values.min()), float(all_values.max())
    edges = np.linspace(minimum, maximum + 1e-9, bins + 1)
    histograms = {name: np.histogram(values, edges)[0] for name, values in values_by_group.items()}
    max_count = max(int(values.max(initial=0)) for values in histograms.values()) or 1
    palette = [BLUE_LIGHT, CRIMSON_LIGHT, ORANGE_LIGHT]
    outlines = [BLUE, CRIMSON, ORANGE]
    bin_width = (right - left) / bins
    group_count = len(histograms)
    for fraction in np.linspace(0, 1, 5):
        y = bottom - fraction * (bottom - top)
        draw.line((left, y, right, y), fill=GRID, width=1)
        draw.text((58, y - 8), str(int(max_count * fraction)), font=_font(13), fill=MUTED)
    for group_index, (name, counts) in enumerate(histograms.items()):
        for bin_index, count in enumerate(counts):
            x0 = left + bin_index * bin_width + group_index * (bin_width / group_count)
            x1 = x0 + bin_width / group_count - 1
            y0 = bottom - count / max_count * (bottom - top)
            draw.rectangle((x0, y0, x1, bottom), fill=palette[group_index % len(palette)], outline=outlines[group_index % len(outlines)], width=1)
        legend_x = 780 + group_index * 130
        draw.rectangle((legend_x, 104, legend_x + 20, 120), fill=palette[group_index % len(palette)], outline=outlines[group_index % len(outlines)])
        draw.text((legend_x + 27, 101), name, font=_font(14), fill=INK)
    for index, value in enumerate(np.linspace(minimum, maximum, 6)):
        x = left + index / 5 * (right - left)
        draw.text((x - 15, bottom + 10), f"{value:.2f}", font=_font(12), fill=MUTED)
    return image


def scatter_chart(
    x: Sequence[float],
    y: Sequence[float],
    groups: Sequence[int],
    title: str,
    subtitle: str = "",
    x_label: str = "dimension 1",
    y_label: str = "dimension 2",
) -> Image.Image:
    image, draw = _canvas(title, subtitle)
    left, top, right, bottom = 105, 165, 1120, 605
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    groups = np.asarray(groups, dtype=int)
    x_min, x_max = float(x.min()), float(x.max())
    y_min, y_max = float(y.min()), float(y.max())
    x_pad = max((x_max - x_min) * 0.08, 0.1)
    y_pad = max((y_max - y_min) * 0.08, 0.1)
    x_min, x_max = x_min - x_pad, x_max + x_pad
    y_min, y_max = y_min - y_pad, y_max + y_pad
    for fraction in np.linspace(0, 1, 6):
        x_grid = left + fraction * (right - left)
        y_grid = bottom - fraction * (bottom - top)
        draw.line((x_grid, top, x_grid, bottom), fill=GRID, width=1)
        draw.line((left, y_grid, right, y_grid), fill=GRID, width=1)
    for x_value, y_value, group in zip(x, y, groups):
        px = left + (x_value - x_min) / max(x_max - x_min, 1e-9) * (right - left)
        py = bottom - (y_value - y_min) / max(y_max - y_min, 1e-9) * (bottom - top)
        fill = CRIMSON if group else BLUE_LIGHT
        outline = CRIMSON if group else BLUE
        radius = 6 if group else 4
        draw.ellipse((px - radius, py - radius, px + radius, py + radius), fill=fill, outline=outline, width=2)
    draw.text((left + 400, bottom + 35), x_label, font=_font(14, True), fill=MUTED)
    draw.text((35, top - 20), y_label, font=_font(14, True), fill=MUTED)
    draw.ellipse((820, 104, 832, 116), fill=BLUE_LIGHT, outline=BLUE, width=2)
    draw.text((840, 101), "benign", font=_font(14), fill=INK)
    draw.ellipse((920, 103, 934, 117), fill=CRIMSON, outline=CRIMSON, width=2)
    draw.text((942, 101), "attack", font=_font(14), fill=INK)
    return image


def matrix_chart(
    matrix: np.ndarray,
    row_labels: Sequence[str],
    column_labels: Sequence[str],
    title: str,
    subtitle: str = "",
) -> Image.Image:
    image, draw = _canvas(title, subtitle)
    values = np.asarray(matrix, dtype=float)
    left, top, right, bottom = 280, 175, 1110, 610
    cell_width = (right - left) / max(len(column_labels), 1)
    cell_height = (bottom - top) / max(len(row_labels), 1)
    maximum = max(float(values.max(initial=1)), 1.0)
    for row_index, label in enumerate(row_labels):
        y = top + row_index * cell_height
        draw.text((55, y + cell_height / 2 - 9), str(label).replace("_", " ")[:27], font=_font(15), fill=INK)
        for column_index, value in enumerate(values[row_index]):
            x = left + column_index * cell_width
            ratio = float(value / maximum)
            red = int(255 - 38 * ratio)
            green = int(245 - 150 * ratio)
            blue = int(238 - 180 * ratio)
            fill = (red, max(green, 70), max(blue, 55))
            draw.rectangle((x, y, x + cell_width - 2, y + cell_height - 2), fill=fill, outline=WHITE)
            draw.text((x + cell_width / 2 - 14, y + cell_height / 2 - 9), f"{value:.0f}", font=_font(14, True), fill=INK if ratio < 0.55 else WHITE)
    for column_index, label in enumerate(column_labels):
        x = left + column_index * cell_width + 6
        draw.text((x, top - 28), str(label)[:13], font=_font(13, True), fill=MUTED)
    return image


def provenance_graph(
    edges: pd.DataFrame,
    title: str = "Process–file–network provenance graph",
    subtitle: str = "Directed synthetic event relationships for one investigation",
) -> Image.Image:
    image, draw = _canvas(title, subtitle)
    if edges.empty:
        draw.text((440, 340), "No matching edges", font=_font(24, True), fill=MUTED)
        return image
    nodes = sorted(set(edges["source"]) | set(edges["target"]))
    by_type: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        by_type[node.split(":", 1)[0]].append(node)
    type_order = ["process", "file", "domain", "resource"]
    x_positions = {"process": 240, "file": 560, "domain": 850, "resource": 1010}
    positions: dict[str, tuple[float, float]] = {}
    for node_type in type_order:
        typed_nodes = by_type.get(node_type, [])
        for index, node in enumerate(typed_nodes):
            y = 175 + (index + 1) / (len(typed_nodes) + 1) * 400
            positions[node] = (x_positions[node_type], y)
    for edge in edges.itertuples(index=False):
        if edge.source not in positions or edge.target not in positions:
            continue
        source = positions[edge.source]
        target = positions[edge.target]
        color = CRIMSON if int(edge.label) else MUTED
        draw.line((source[0], source[1], target[0], target[1]), fill=color, width=2)
        angle = math.atan2(target[1] - source[1], target[0] - source[0])
        arrow = (
            target[0] - 13 * math.cos(angle) + 7 * math.cos(angle + math.pi / 2),
            target[1] - 13 * math.sin(angle) + 7 * math.sin(angle + math.pi / 2),
            target[0] - 13 * math.cos(angle) - 7 * math.cos(angle + math.pi / 2),
            target[1] - 13 * math.sin(angle) - 7 * math.sin(angle + math.pi / 2),
        )
        draw.polygon([(target[0], target[1]), (arrow[0], arrow[1]), (arrow[2], arrow[3])], fill=color)
    node_colors = {"process": ORANGE_LIGHT, "file": BLUE_LIGHT, "domain": CRIMSON_LIGHT, "resource": "#FDE68A"}
    node_outlines = {"process": ORANGE, "file": BLUE, "domain": CRIMSON, "resource": GOLD}
    for node, (x, y) in positions.items():
        node_type, label = node.split(":", 1)
        radius = 21
        draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=node_colors[node_type], outline=node_outlines[node_type], width=3)
        draw.text((x + 29, y - 10), label[:25], font=_font(13), fill=INK)
    for node_type in type_order:
        if by_type.get(node_type):
            draw.text((x_positions[node_type] - 45, 145), node_type.upper(), font=_font(13, True), fill=MUTED)
    return image


def dashboard_preview(summary: dict[str, str], charts: Sequence[Image.Image]) -> Image.Image:
    """Compose a static README preview of the Streamlit app visual language."""

    canvas = Image.new("RGB", (1500, 780), WHITE)
    draw = ImageDraw.Draw(canvas)
    draw.rectangle((0, 0, 1500, 112), fill=INK)
    draw.text((54, 28), "MacSentinel", font=_font(40, True), fill=WHITE)
    draw.text((315, 42), "macOS threat detection · provenance graphs · streaming ML", font=_font(20), fill="#D0D5DD")
    card_width = 330
    for index, (label, value) in enumerate(summary.items()):
        x0 = 54 + index * (card_width + 24)
        draw.rounded_rectangle((x0, 145, x0 + card_width, 265), radius=18, fill=PAPER, outline=GRID, width=2)
        draw.text((x0 + 24, 169), label, font=_font(16, True), fill=MUTED)
        draw.text((x0 + 24, 205), value, font=_font(33, True), fill=CRIMSON if index == 2 else INK)
    slots = [(54, 305, 725, 742), (775, 305, 1446, 742)]
    for chart, slot in zip(charts[:2], slots):
        resized = chart.copy()
        resized.thumbnail((slot[2] - slot[0], slot[3] - slot[1]))
        canvas.paste(resized, (slot[0], slot[1]))
    return canvas
