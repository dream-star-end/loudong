"""Report generation — HTML dual report per PRD §3.7.

Generates:
1. Developer report: findings organized by WSTG/ASVS/OWASP Top 10, with fix advice.
2. Agent self-reflection report: token usage, tool calls, coverage metrics.
"""

import html
from datetime import UTC, datetime
from typing import Any

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def generate_dev_report(
    target_name: str,
    hosts: list[str],
    findings: list[dict[str, Any]],
    scan_stats: dict[str, Any] | None = None,
) -> str:
    """Generate an HTML report for developers with findings and fix advice."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        label = SEVERITY_LABELS.get(sev, sev)
        title = html.escape(f.get("title", ""))
        desc = html.escape(f.get("description", ""))
        cat = html.escape(f.get("category", ""))
        wstg = ", ".join(f.get("wstg_refs", []))
        asvs = ", ".join(f.get("asvs_refs", []))
        top10 = ", ".join(f.get("top10_refs", []))
        conf = f.get("confidence", 0)
        status = f.get("status", "needs_review")

        findings_html += f"""
        <div style="border-left:4px solid {color};background:#0f0f2e;padding:16px;margin:12px 0;border-radius:8px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                <span style="background:{color};color:white;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:700;">{label}</span>
                <strong style="color:white;">#{i} {title}</strong>
                <span style="margin-left:auto;font-size:12px;color:#9ca3af;">置信度 {int(conf*100)}% | {status}</span>
            </div>
            <p style="color:#d1d5db;font-size:14px;margin:8px 0;">{desc}</p>
            <div style="font-size:12px;color:#9ca3af;">
                <span>类别: {cat}</span>
                {f' | WSTG: {wstg}' if wstg else ''}
                {f' | ASVS: {asvs}' if asvs else ''}
                {f' | OWASP Top 10: {top10}' if top10 else ''}
            </div>
        </div>"""

    sev_summary = " | ".join(
        f'<span style="color:{SEVERITY_COLORS.get(s,"#fff")}">{SEVERITY_LABELS.get(s,s)}: {c}</span>'
        for s, c in sorted(sev_counts.items(), key=lambda x: -SEVERITY_COLORS.get(x[0], 0).__hash__())
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VulnHunter 安全测试报告 — {html.escape(target_name)}</title>
<style>
body{{font-family:'Inter',system-ui,sans-serif;background:#0a0a1a;color:#e5e7eb;margin:0;padding:40px;}}
.container{{max-width:900px;margin:0 auto;}}
h1{{background:linear-gradient(135deg,#a855f7,#06b6d4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:28px;}}
h2{{color:#a855f7;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:8px;margin-top:32px;}}
.meta{{color:#9ca3af;font-size:13px;margin:8px 0 24px;}}
.stats{{display:flex;gap:16px;margin:16px 0;}}
.stat{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:16px 24px;flex:1;text-align:center;}}
.stat-num{{font-size:28px;font-weight:700;color:white;}}
.stat-label{{font-size:12px;color:#9ca3af;margin-top:4px;}}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ VulnHunter 安全测试报告</h1>
<div class="meta">目标: {html.escape(target_name)} ({', '.join(html.escape(h) for h in hosts)}) | 生成时间: {now}</div>

<div class="stats">
<div class="stat"><div class="stat-num">{len(findings)}</div><div class="stat-label">发现总数</div></div>
<div class="stat"><div class="stat-num" style="color:#dc2626">{sev_counts.get('critical',0)+sev_counts.get('high',0)}</div><div class="stat-label">严重/高危</div></div>
<div class="stat"><div class="stat-num" style="color:#d97706">{sev_counts.get('medium',0)}</div><div class="stat-label">中危</div></div>
<div class="stat"><div class="stat-num" style="color:#2563eb">{sev_counts.get('low',0)+sev_counts.get('info',0)}</div><div class="stat-label">低危/信息</div></div>
</div>

<h2>严重程度概览</h2>
<p>{sev_summary}</p>

<h2>漏洞详情</h2>
{findings_html if findings_html else '<p style="color:#6b7280;">未发现安全问题。</p>'}

<hr style="border-color:rgba(255,255,255,0.05);margin:32px 0;">
<p style="font-size:11px;color:#4b5563;">此报告由 VulnHunter AI Agent 自动生成, 基于 WSTG / ASVS / OWASP Top 10 标准。</p>
</div>
</body>
</html>"""


def generate_agent_report(
    target_name: str,
    agent_stats: list[dict[str, Any]],
    evidence_stats: dict[str, Any] | None = None,
    total_tokens: int = 0,
) -> str:
    """Generate agent self-reflection report with operational metrics."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for a in agent_stats:
        rows += f"""<tr>
            <td style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.05);">{html.escape(a.get('name',''))}</td>
            <td style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.05);">{a.get('status','')}</td>
            <td style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.05);">{a.get('tool_calls',0)}</td>
            <td style="padding:8px;border-bottom:1px solid rgba(255,255,255,0.05);">{a.get('findings_count',0)}</td>
        </tr>"""

    ev = evidence_stats or {}

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><title>VulnHunter Agent 自省报告</title>
<style>
body{{font-family:'Inter',system-ui,sans-serif;background:#0a0a1a;color:#e5e7eb;margin:0;padding:40px;}}
.container{{max-width:900px;margin:0 auto;}}
h1{{color:#06b6d4;font-size:24px;}}
h2{{color:#a855f7;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:8px;margin-top:32px;}}
table{{width:100%;border-collapse:collapse;}}
th{{text-align:left;padding:8px;color:#9ca3af;font-size:12px;border-bottom:1px solid rgba(255,255,255,0.1);}}
td{{font-size:14px;}}
.metric{{background:rgba(255,255,255,0.04);border-radius:8px;padding:12px 16px;margin:8px 0;display:flex;justify-content:space-between;}}
</style>
</head>
<body>
<div class="container">
<h1>🤖 Agent 自省报告</h1>
<p style="color:#9ca3af;font-size:13px;">目标: {html.escape(target_name)} | 时间: {now}</p>

<h2>Agent 执行统计</h2>
<table>
<tr><th>Agent</th><th>状态</th><th>工具调用</th><th>发现数</th></tr>
{rows}
</table>

<h2>证据统计</h2>
<div class="metric"><span>原始发现</span><span>{ev.get('total_raw',0)}</span></div>
<div class="metric"><span>去重后</span><span>{ev.get('after_dedup',0)}</span></div>
<div class="metric"><span>已确认</span><span>{ev.get('confirmed',0)}</span></div>
<div class="metric"><span>待审核</span><span>{ev.get('needs_review',0)}</span></div>
<div class="metric"><span>LLM Token 消耗</span><span>{total_tokens}</span></div>

<hr style="border-color:rgba(255,255,255,0.05);margin:32px 0;">
<p style="font-size:11px;color:#4b5563;">VulnHunter Agent 内部运行报告。</p>
</div>
</body>
</html>"""
