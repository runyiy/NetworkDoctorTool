"""ISP report renderer — produces a polished PDF with charts."""

from __future__ import annotations

import logging
from pathlib import Path

from losshound.core.isp_report import IspReportData

logger = logging.getLogger(__name__)


def _render_latency_chart_png(observations: list[dict]) -> bytes | None:
    """Render a latency-over-time chart and return PNG bytes, or None."""
    if not observations:
        return None
    try:
        import io
        import matplotlib
        matplotlib.use("Agg")  # headless backend, no GUI dependency
        import matplotlib.pyplot as plt
        from datetime import datetime as _dt

        timestamps, public_rtt, gateway_rtt = [], [], []
        for o in observations:
            try:
                t = _dt.fromisoformat(o["timestamp"])
            except (TypeError, ValueError):
                continue
            timestamps.append(t)
            public_rtt.append(o.get("public_rtt"))
            gateway_rtt.append(o.get("gateway_rtt"))

        if not timestamps:
            return None

        fig, ax = plt.subplots(figsize=(7.5, 3.0), dpi=110)
        ax.plot(timestamps, public_rtt, label="Public (avg)",
                color="#cba6f7", linewidth=1.5)
        ax.plot(timestamps, gateway_rtt, label="Gateway",
                color="#89b4fa", linewidth=1.0, linestyle="--")
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Latency over time")
        ax.legend(loc="upper right", fontsize=8)
        ax.grid(True, alpha=0.3)
        fig.autofmt_xdate()
        fig.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=110)
        plt.close(fig)
        return buf.getvalue()
    except Exception:
        logger.exception("Failed to render latency chart")
        return None


def _render_loss_chart_png(observations: list[dict]) -> bytes | None:
    if not observations:
        return None
    try:
        import io
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from datetime import datetime as _dt

        timestamps, losses = [], []
        for o in observations:
            try:
                t = _dt.fromisoformat(o["timestamp"])
            except (TypeError, ValueError):
                continue
            timestamps.append(t)
            losses.append((o.get("public_loss") or 0.0))

        if not timestamps:
            return None

        fig, ax = plt.subplots(figsize=(7.5, 2.4), dpi=110)
        ax.fill_between(timestamps, 0, losses, color="#f38ba8", alpha=0.6)
        ax.set_ylabel("Packet loss (%)")
        ax.set_title("Packet loss over time")
        ax.set_ylim(bottom=0)
        ax.grid(True, alpha=0.3)
        fig.autofmt_xdate()
        fig.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=110)
        plt.close(fig)
        return buf.getvalue()
    except Exception:
        logger.exception("Failed to render loss chart")
        return None


def _render_dns_bar_png(benchmarks: list[dict]) -> bytes | None:
    if not benchmarks:
        return None
    try:
        import io
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels, values = [], []
        for b in benchmarks[-8:]:
            label = b.get("label") or b.get("timestamp", "")[:10]
            dns = b.get("avg_dns_ms")
            if dns is None:
                continue
            labels.append(label)
            values.append(dns)

        if not values:
            return None

        fig, ax = plt.subplots(figsize=(7.5, 2.8), dpi=110)
        ax.bar(labels, values, color="#a6e3a1")
        ax.set_ylabel("DNS resolution time (ms)")
        ax.set_title("DNS performance (recent benchmarks)")
        ax.grid(True, axis="y", alpha=0.3)
        fig.autofmt_xdate()
        fig.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=110)
        plt.close(fig)
        return buf.getvalue()
    except Exception:
        logger.exception("Failed to render DNS bar chart")
        return None


def _render_before_after_png(benchmarks: list[dict]) -> bytes | None:
    before = next((b for b in benchmarks if b.get("label") == "before"), None)
    after = next((b for b in benchmarks if b.get("label") == "after"), None)
    if not before or not after:
        return None
    try:
        import io
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        metrics = [
            ("Latency (ms)", "avg_latency_ms"),
            ("Jitter (ms)",  "avg_jitter_ms"),
            ("Loss (%)",     "avg_loss_pct"),
            ("DNS (ms)",     "avg_dns_ms"),
        ]
        labels = [m[0] for m in metrics]
        before_vals = [before.get(k) or 0 for _, k in metrics]
        after_vals  = [after.get(k)  or 0 for _, k in metrics]

        import numpy as np
        x = np.arange(len(labels))
        width = 0.35

        fig, ax = plt.subplots(figsize=(7.5, 3.0), dpi=110)
        ax.bar(x - width / 2, before_vals, width, label="Before", color="#f9e2af")
        ax.bar(x + width / 2, after_vals,  width, label="After",  color="#a6e3a1")
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_title("Before vs after optimization")
        ax.legend()
        ax.grid(True, axis="y", alpha=0.3)
        fig.tight_layout()

        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=110)
        plt.close(fig)
        return buf.getvalue()
    except Exception:
        logger.exception("Failed to render before/after chart")
        return None


def _embed_image_section(title: str, png: bytes | None, story, styles,
                         width: int = 460, height: int = 180):
    import io
    from reportlab.platypus import Paragraph, Spacer, Image

    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story.append(Paragraph(title, h2))
    if png is None:
        story.append(Paragraph("Not enough data.", body))
    else:
        story.append(Image(io.BytesIO(png), width=width, height=height))
    story.append(Spacer(1, 12))


def _build_benchmark_table(data, story, styles):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors

    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story.append(Paragraph("Recent benchmarks", h2))
    if not data.benchmarks:
        story.append(Paragraph("No benchmarks recorded.", body))
        story.append(Spacer(1, 12))
        return

    rows = [["When", "Label", "Latency", "Jitter", "Loss", "DNS", "Score"]]
    for b in data.benchmarks[-10:]:
        rows.append([
            (b.get("timestamp", "") or "")[:19],
            b.get("label", "") or "",
            f"{b.get('avg_latency_ms') or 0:.1f} ms",
            f"{b.get('avg_jitter_ms') or 0:.1f} ms",
            f"{b.get('avg_loss_pct') or 0:.1f}%",
            f"{b.get('avg_dns_ms') or 0:.1f} ms",
            f"{b.get('overall_score') or 0:.0f}",
        ])

    table = Table(rows, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#313244")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#6c7086")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f5f5f7"), colors.white]),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))


def _build_diagnosis_log(data, story, styles):
    from reportlab.platypus import Paragraph, Spacer

    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story.append(Paragraph("Recent diagnoses", h2))
    if not data.diagnoses:
        story.append(Paragraph("No diagnoses recorded.", body))
        story.append(Spacer(1, 12))
        return

    lines = []
    for d in data.diagnoses[:15]:
        ts = (d.get("timestamp", "") or "")[:19]
        cat = d.get("category", "")
        summary = (d.get("summary", "") or "").replace("&", "&amp;")
        lines.append(f"<b>{ts}</b> [{cat}] — {summary}")
    story.append(Paragraph("<br/>".join(lines), body))
    story.append(Spacer(1, 12))


def _build_route_table(data, story, styles):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors

    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story.append(Paragraph("Latest route", h2))
    route = data.latest_route or []
    if not route:
        story.append(Paragraph("No route data available.", body))
        story.append(Spacer(1, 12))
        return

    rows = [["Hop", "IP", "RTT samples"]]
    for h in route[:20]:
        rtt = h.get("rtt", [])
        rtt_str = ", ".join(
            f"{x:.0f}ms" if isinstance(x, (int, float)) else "—"
            for x in rtt
        )
        rows.append([str(h.get("hop", "")), h.get("ip") or "—", rtt_str])

    table = Table(rows, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#313244")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#6c7086")),
    ]))
    story.append(table)


def render_isp_report_pdf(data: IspReportData, output_path: Path) -> Path:
    """Render ``data`` as a styled PDF written to ``output_path``.

    Returns the output path on success. Raises ImportError if reportlab
    or matplotlib are missing, OSError on I/O failures.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate
    except ImportError as exc:
        raise ImportError(
            "reportlab is required for PDF export. "
            "Install with: pip install reportlab>=4.0"
        ) from exc

    output_path = Path(output_path)
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=2 * 28, rightMargin=2 * 28,
        topMargin=2 * 28, bottomMargin=2 * 28,
        title="Losshound ISP Report",
        author="Losshound",
    )
    story = []
    styles = getSampleStyleSheet()
    _build_cover_page(data, story, styles)
    _build_system_info(data, story, styles)
    _build_issue_summary(data, story, styles)
    _embed_image_section(
        "Latency",
        _render_latency_chart_png(data.observations),
        story, styles, width=460, height=180,
    )
    _embed_image_section(
        "Packet loss",
        _render_loss_chart_png(data.observations),
        story, styles, width=460, height=144,
    )
    _embed_image_section(
        "DNS performance",
        _render_dns_bar_png(data.benchmarks),
        story, styles, width=460, height=168,
    )
    _embed_image_section(
        "Before vs after",
        _render_before_after_png(data.benchmarks),
        story, styles, width=460, height=180,
    )
    _build_benchmark_table(data, story, styles)
    _build_diagnosis_log(data, story, styles)
    _build_route_table(data, story, styles)
    doc.build(story)
    return output_path


def _build_system_info(data, story, styles):
    from reportlab.platypus import Paragraph, Spacer

    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story.append(Paragraph("System environment", h2))
    si = data.system_info or {}
    lines = [
        f"<b>OS:</b> {si.get('os', 'Unknown')}",
        f"<b>Hostname:</b> {si.get('hostname', 'Unknown')}",
        f"<b>Default gateway:</b> {si.get('default_gateway', 'Unknown')}",
    ]
    for adapter in si.get("active_adapters", []):
        lines.append(
            f"<b>Adapter:</b> {adapter.get('description', '')} "
            f"({adapter.get('link_speed', '')})"
        )
    story.append(Paragraph("<br/>".join(lines), body))
    story.append(Spacer(1, 12))


def _build_issue_summary(data, story, styles):
    from reportlab.platypus import Paragraph, Spacer

    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story.append(Paragraph("Issue summary", h2))
    if not data.issue_counts:
        story.append(Paragraph("No issues recorded in this window.", body))
    else:
        rows = [
            f"<b>{cat}:</b> {count} occurrence{'s' if count != 1 else ''}"
            for cat, count in sorted(data.issue_counts.items(),
                                     key=lambda kv: -kv[1])
        ]
        story.append(Paragraph("<br/>".join(rows), body))
    story.append(Spacer(1, 12))


def _build_cover_page(data, story, styles):
    from reportlab.platypus import Paragraph, Spacer

    title_style = styles["Title"]
    body_style = styles["BodyText"]

    story.append(Paragraph("Losshound — ISP Network Quality Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"Generated: {data.generated_at[:19]}<br/>"
        f"Report period: last {data.report_period_hours} hours<br/>"
        f"Score: {data.avg_score:.0f}/100 (Grade {data.latest_grade or 'N/A'})"
        if data.avg_score is not None
        else f"Generated: {data.generated_at[:19]}<br/>"
             f"Report period: last {data.report_period_hours} hours",
        body_style,
    ))
    story.append(Spacer(1, 24))
