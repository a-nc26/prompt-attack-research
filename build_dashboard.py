#!/usr/bin/env python3
"""
build_dashboard.py  –  v2 Precision Dashboard
-----------------------------------------------
Reads master_db_v2.json (falls back to master_db.json) and generates a
self-contained dark-theme HTML dashboard.

Outputs:
  - ~/Desktop/prompt_attack_taxonomy.html  (always overwritten)
  - ~/ai_security_research/reports/taxonomy_YYYYMMDD.html  (dated archive)

Usage:
    python3 build_dashboard.py
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR       = os.path.expanduser("~/ai_security_research/data")
REPORTS_DIR    = os.path.expanduser("~/ai_security_research/reports")
DESKTOP_OUTPUT = os.path.expanduser("~/Desktop/prompt_attack_taxonomy.html")
DATE_STR       = datetime.now().strftime("%Y%m%d")
ARCHIVE_OUTPUT = os.path.join(REPORTS_DIR, f"taxonomy_{DATE_STR}.html")

# v2 preferred, fall back to v1
V2_PATH = os.path.join(DATA_DIR, "master_db_v2.json")
V1_PATH = os.path.join(DATA_DIR, "master_db.json")

# ---------------------------------------------------------------------------
# Colour maps
# ---------------------------------------------------------------------------
CATEGORY_COLORS = {
    "Role & Persona Manipulation":    "#ef4444",
    "Instruction Hierarchy Attacks":  "#f97316",
    "Encoding & Obfuscation":         "#84cc16",
    "Fictional Framing":              "#14b8a6",
    "Social Engineering":             "#ec4899",
    "Divide & Conquer / Multi-turn":  "#8b5cf6",
    "Indirect & Prompt Injection":    "#06b6d4",
    "Model Extraction":               "#6366f1",
    "Defense & Red-team Research":    "#22c55e",
    "Other/Unclassified":             "#64748b",
}

SEVERITY_COLORS = {
    "High":   "#ef4444",
    "Medium": "#f97316",
    "Low":    "#eab308",
    "Info":   "#6366f1",
}


# ---------------------------------------------------------------------------
# Load DB
# ---------------------------------------------------------------------------

def load_db():
    path = V2_PATH if os.path.exists(V2_PATH) else V1_PATH
    if not os.path.exists(path):
        print(f"WARN: No database found. Generating empty dashboard.", file=sys.stderr)
        return []
    print(f"Loading from: {path}")
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse DB: {e}", file=sys.stderr)
            return []


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def esc(s):
    """HTML-escape for text content."""
    if not isinstance(s, str):
        s = str(s) if s is not None else ""
    return (s.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;")
              .replace('"', "&quot;")
              .replace("'", "&#39;"))


def attr_val(s):
    """Escape for HTML attribute values — does NOT encode & so JS .value reads literal chars."""
    if not isinstance(s, str):
        s = str(s) if s is not None else ""
    return (s.replace('"', "&quot;")
              .replace("'", "&#39;")
              .replace("<", "&lt;")
              .replace(">", "&gt;"))


def build_html(all_posts: list) -> str:
    # Filter to ONLY relevant posts for display
    posts = [p for p in all_posts if p.get("relevant") is True]

    # Stats (based on relevant posts)
    total_techniques  = len(posts)
    with_prompts      = sum(1 for p in posts if p.get("has_actual_prompt"))
    high_count        = sum(1 for p in posts if p.get("severity") == "High")
    cats_covered      = len({p.get("taxonomy_category", "") for p in posts
                             if p.get("taxonomy_category") and p["taxonomy_category"] != "Other/Unclassified"})
    last_updated      = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Category counts for sidebar (relevant posts only)
    cat_counts = Counter(p.get("taxonomy_category", "Other/Unclassified") for p in posts)

    # Dropdowns
    categories = sorted({p.get("taxonomy_category", "") for p in posts if p.get("taxonomy_category")})
    severities = ["High", "Medium", "Low", "Info"]

    cat_options_html = "\n".join(
        f'<option value="{attr_val(c)}">{esc(c)}</option>' for c in categories
    )
    sev_options_html = "\n".join(
        f'<option value="{attr_val(s)}">{esc(s)}</option>' for s in severities
    )

    # Sidebar items (data-cat avoids HTML-entity-encoding issues in onclick)
    sidebar_items_html = (
        '<div class="sidebar-item sidebar-all" data-cat="">'
        '<span class="sidebar-cat">All</span>'
        f'<span class="sidebar-count">{len(posts)}</span>'
        '</div>'
    )
    sidebar_items_html += "\n".join(
        f'<div class="sidebar-item" data-cat="{attr_val(cat)}">'
        f'<span class="sidebar-cat">{esc(cat)}</span>'
        f'<span class="sidebar-count">{count}</span>'
        f'</div>'
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1])
    )

    # Build JS data array (only relevant posts)
    js_rows = []
    for p in posts:
        js_rows.append({
            "id":                   p.get("id", "") or "",
            "title":                p.get("title", "") or "",
            "selftext":             (p.get("selftext", "") or "")[:1000],
            "author":               p.get("author", "") or "",
            "subreddit":            p.get("subreddit", "") or "",
            "permalink":            p.get("permalink", "") or "",
            "post_date":            p.get("post_date", "") or "",
            "score":                int(p.get("score", 0) or 0),
            "num_comments":         int(p.get("num_comments", 0) or 0),
            "taxonomy_category":    p.get("taxonomy_category", "Other/Unclassified") or "Other/Unclassified",
            "technique_name":       p.get("technique_name", "") or "",
            "technique_description": p.get("technique_description", "") or "",
            "persona_role":         p.get("persona_role") or None,
            "severity":             p.get("severity", "Info") or "Info",
            "has_actual_prompt":    bool(p.get("has_actual_prompt")),
            "example_prompt":       p.get("example_prompt") or None,
        })

    js_data        = json.dumps(js_rows, ensure_ascii=False)
    js_cat_colors  = json.dumps(CATEGORY_COLORS, ensure_ascii=False)
    js_sev_colors  = json.dumps(SEVERITY_COLORS, ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Prompt Attack Taxonomy Dashboard</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:       #0f1117;
    --card:     #1a1d2e;
    --card2:    #141622;
    --border:   #2d3149;
    --accent:   #6366f1;
    --accent2:  #818cf8;
    --text:     #e2e8f0;
    --muted:    #94a3b8;
    --high:     #ef4444;
    --medium:   #f97316;
    --low:      #eab308;
    --info:     #6366f1;
    --hover:    #252840;
    --header:   #0d1117;
  }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    min-height: 100vh;
  }}

  /* HEADER */
  .header {{
    background: var(--header);
    border-bottom: 1px solid var(--border);
    padding: 18px 24px 14px;
  }}
  .header h1 {{ font-size: 20px; font-weight: 700; color: var(--accent2); letter-spacing: -0.4px; }}
  .header p  {{ color: var(--muted); font-size: 11px; margin-top: 3px; }}

  /* STATS BAR */
  .stats-bar {{
    display: flex;
    gap: 12px;
    padding: 14px 24px;
    background: var(--header);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 18px;
    min-width: 130px;
    flex: 1;
  }}
  .stat-card .label {{ color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.6px; }}
  .stat-card .value {{ font-size: 22px; font-weight: 700; color: var(--accent2); margin-top: 4px; }}
  .stat-card.high-card .value {{ color: var(--high); }}
  .stat-card .value.small   {{ font-size: 12px; margin-top: 6px; color: var(--text); }}

  /* LAYOUT */
  .layout {{
    display: flex;
    height: calc(100vh - 152px);
    min-height: 500px;
  }}

  /* SIDEBAR */
  .sidebar {{
    width: 200px;
    min-width: 200px;
    background: var(--card2);
    border-right: 1px solid var(--border);
    overflow-y: auto;
    padding: 10px 0;
    position: sticky;
    top: 0;
    display: flex;
    flex-direction: column;
  }}
  .sidebar-header {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--muted);
    padding: 0 12px 8px;
    font-weight: 600;
  }}
  .sidebar-item {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 12px;
    cursor: pointer;
    border-radius: 4px;
    margin: 1px 5px;
    transition: background 0.12s;
  }}
  .sidebar-item:hover {{ background: var(--hover); }}
  .sidebar-item.active {{ background: var(--accent); }}
  .sidebar-item.active .sidebar-cat {{ color: #fff; }}
  .sidebar-item.active .sidebar-count {{ background: rgba(255,255,255,0.2); color: #fff; }}
  .sidebar-cat {{ font-size: 12px; color: var(--text); flex: 1; word-break: break-word; line-height: 1.3; }}
  .sidebar-count {{
    font-size: 10px; font-weight: 600; color: var(--muted);
    background: var(--border); border-radius: 9px;
    padding: 1px 6px; margin-left: 5px; flex-shrink: 0;
  }}

  /* Severity legend at sidebar bottom */
  .sidebar-legend {{
    margin-top: auto;
    border-top: 1px solid var(--border);
    padding: 10px 12px 6px;
  }}
  .sidebar-legend .leg-title {{
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.6px;
    color: var(--muted); margin-bottom: 6px; font-weight: 600;
  }}
  .leg-row {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; font-size: 11px; }}
  .leg-dot  {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}

  /* MAIN */
  .main {{
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }}

  /* FILTER ROW */
  .filters {{
    background: var(--card2);
    border-bottom: 1px solid var(--border);
    padding: 8px 14px;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
  }}
  .filters input, .filters select {{
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    outline: none;
    transition: border-color 0.12s;
  }}
  .filters input:focus, .filters select:focus {{ border-color: var(--accent); }}
  .filters input  {{ min-width: 180px; flex: 1; }}
  .filters select {{ min-width: 150px; }}
  .btn {{
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    padding: 5px 12px;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.12s;
    white-space: nowrap;
  }}
  .btn:hover {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
  .btn.active  {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
  .btn.prompt-active {{ background: #14532d; border-color: #22c55e; color: #22c55e; }}
  .result-count {{ color: var(--muted); font-size: 11px; margin-left: auto; white-space: nowrap; }}

  /* TABLE */
  .table-wrap {{ flex: 1; overflow: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead th {{
    background: var(--header);
    border-bottom: 2px solid var(--border);
    padding: 8px 10px;
    text-align: left;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--muted);
    position: sticky; top: 0; z-index: 10;
    cursor: pointer; user-select: none; white-space: nowrap;
  }}
  thead th:hover {{ color: var(--accent2); }}
  thead th.sorted {{ color: var(--accent2); }}
  thead th .sort-icon {{ margin-left: 3px; opacity: 0.45; }}
  thead th.sorted .sort-icon {{ opacity: 1; }}

  tbody tr {{ border-bottom: 1px solid var(--border); transition: background 0.1s; }}
  tbody tr:nth-child(odd)  {{ background: var(--card); }}
  tbody tr:nth-child(even) {{ background: var(--card2); }}
  tbody tr:hover {{ background: var(--hover); }}
  tbody td {{ padding: 8px 10px; vertical-align: top; }}

  /* SEVERITY BADGES */
  .sev-badge {{
    display: inline-block; padding: 2px 7px; border-radius: 4px;
    font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px;
    white-space: nowrap;
  }}
  .sev-High   {{ background: rgba(239,68,68,0.15);  color: var(--high);   border: 1px solid rgba(239,68,68,0.35); }}
  .sev-Medium {{ background: rgba(249,115,22,0.15); color: var(--medium); border: 1px solid rgba(249,115,22,0.35); }}
  .sev-Low    {{ background: rgba(234,179,8,0.15);  color: var(--low);    border: 1px solid rgba(234,179,8,0.35); }}
  .sev-Info   {{ background: rgba(99,102,241,0.15); color: var(--info);   border: 1px solid rgba(99,102,241,0.35); }}

  /* CATEGORY PILL */
  .cat-pill {{
    display: inline-block; padding: 2px 8px; border-radius: 20px;
    font-size: 11px; font-weight: 500; border: 1px solid;
    white-space: nowrap; max-width: 170px;
    overflow: hidden; text-overflow: ellipsis;
  }}

  /* TECHNIQUE NAME */
  .tech-name {{ font-weight: 600; font-size: 12px; color: var(--text); line-height: 1.4; }}
  .tech-desc  {{ font-size: 11px; color: var(--muted); margin-top: 3px; line-height: 1.4; }}

  /* PERSONA */
  .persona-tag {{
    background: rgba(139,92,246,0.15); border: 1px solid rgba(139,92,246,0.3);
    color: #c4b5fd; border-radius: 4px; padding: 1px 6px; font-size: 11px; font-style: italic;
  }}
  .no-persona {{ color: #555; font-size: 12px; }}

  /* PROMPT BLOCK */
  .prompt-block {{
    background: #0d1117; color: #39d353;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    padding: 8px; border-radius: 4px; font-size: 0.8em;
    max-height: 120px; overflow-y: auto; white-space: pre-wrap;
    border: 1px solid #2d3149; word-break: break-word;
    margin-top: 2px;
  }}
  .no-prompt {{ color: #555; font-size: 11px; font-style: italic; }}

  /* SOURCE */
  .sub-badge {{
    display: inline-block; background: rgba(99,102,241,0.12);
    border: 1px solid rgba(99,102,241,0.25); border-radius: 4px;
    padding: 1px 6px; font-size: 11px; color: var(--accent2);
    white-space: nowrap;
  }}
  .src-link {{
    color: var(--accent2); text-decoration: none; font-size: 11px;
  }}
  .src-link:hover {{ text-decoration: underline; }}
  .ext-icon {{ font-size: 10px; margin-left: 2px; opacity: 0.7; }}

  /* DATE */
  .date-cell {{ color: var(--muted); font-size: 11px; white-space: nowrap; }}

  /* NO RESULTS */
  .no-results {{ padding: 60px; text-align: center; color: var(--muted); }}

  /* SCROLLBAR */
  ::-webkit-scrollbar {{ width: 5px; height: 5px; }}
  ::-webkit-scrollbar-track {{ background: transparent; }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--accent); }}
</style>
</head>
<body>

<div class="header">
  <h1>AI Prompt Attack Taxonomy Dashboard</h1>
  <p>Precision-classified AI jailbreak &amp; prompt injection techniques from Reddit &mdash; relevant posts only</p>
</div>

<!-- TOP STATS BAR: 5 cards -->
<div class="stats-bar">
  <div class="stat-card">
    <div class="label">Total Techniques</div>
    <div class="value">{total_techniques}</div>
  </div>
  <div class="stat-card">
    <div class="label">With Actual Prompts</div>
    <div class="value">{with_prompts}</div>
  </div>
  <div class="stat-card high-card">
    <div class="label">High Severity</div>
    <div class="value">{high_count}</div>
  </div>
  <div class="stat-card">
    <div class="label">Categories Covered</div>
    <div class="value">{cats_covered}</div>
  </div>
  <div class="stat-card">
    <div class="label">Last Updated</div>
    <div class="value small">{last_updated}</div>
  </div>
</div>

<div class="layout">

  <!-- LEFT SIDEBAR: sticky 200px, taxonomy + severity legend -->
  <div class="sidebar">
    <div class="sidebar-header">Taxonomy</div>
    <div id="sidebarItems">
{sidebar_items_html}
    </div>

    <div class="sidebar-legend">
      <div class="leg-title">Severity</div>
      <div class="leg-row"><div class="leg-dot" style="background:#ef4444"></div> High</div>
      <div class="leg-row"><div class="leg-dot" style="background:#f97316"></div> Medium</div>
      <div class="leg-row"><div class="leg-dot" style="background:#eab308"></div> Low</div>
      <div class="leg-row"><div class="leg-dot" style="background:#6366f1"></div> Info</div>
    </div>
  </div>

  <!-- MAIN CONTENT -->
  <div class="main">

    <!-- FILTER ROW -->
    <div class="filters">
      <input type="text" id="searchBox" placeholder="Search technique, prompt, description, title..." oninput="applyFilters()">
      <select id="catFilter" onchange="applyFilters()">
        <option value="">All Categories</option>
        {cat_options_html}
      </select>
      <select id="sevFilter" onchange="applyFilters()">
        <option value="">All Severities</option>
        {sev_options_html}
      </select>
      <button class="btn" id="promptToggleBtn" onclick="toggleHasPrompt()">Has Prompt</button>
      <button class="btn" onclick="clearAllFilters()">Clear Filters</button>
      <span class="result-count" id="resultCount"></span>
    </div>

    <!-- MAIN TABLE -->
    <div class="table-wrap" id="tableWrap">
      <table id="mainTable">
        <thead>
          <tr>
            <th data-col="severity"          onclick="sortTable('severity')">Sev <span class="sort-icon">&#8597;</span></th>
            <th data-col="taxonomy_category" onclick="sortTable('taxonomy_category')">Category <span class="sort-icon">&#8597;</span></th>
            <th data-col="technique_name"    onclick="sortTable('technique_name')">Technique Name <span class="sort-icon">&#8597;</span></th>
            <th data-col="persona_role"      onclick="sortTable('persona_role')">Persona/Role <span class="sort-icon">&#8597;</span></th>
            <th data-col="technique_description">Technique Description</th>
            <th data-col="example_prompt">Example Prompt</th>
            <th data-col="subreddit"         onclick="sortTable('subreddit')">Source <span class="sort-icon">&#8597;</span></th>
            <th data-col="post_date"         onclick="sortTable('post_date')">Date <span class="sort-icon">&#8597;</span></th>
          </tr>
        </thead>
        <tbody id="tableBody"></tbody>
      </table>
      <div class="no-results" id="noResults" style="display:none">No entries match the current filters.</div>
    </div>

  </div>
</div>

<script>
// DATA contains ONLY relevant=true posts (pre-filtered in Python)
const DATA = {js_data};
const CAT_COLORS = {js_cat_colors};
const SEV_COLORS = {js_sev_colors};
const SEV_ORDER  = {{High:0,Medium:1,Low:2,Info:3}};

let sortCol        = 'severity';
let sortDir        = 'asc';
let activeCategory = null;  // null = All
let showHasPromptOnly = false;

// ---- Sidebar click handler (uses data-cat, not encoded onclick args) ----
document.getElementById('sidebarItems').addEventListener('click', function(e) {{
  const item = e.target.closest('.sidebar-item');
  if (!item) return;
  const cat = item.dataset.cat;  // "" means All
  activeCategory = (cat === '') ? null : cat;
  document.querySelectorAll('.sidebar-item').forEach(function(el) {{
    el.classList.toggle('active', el.dataset.cat === (activeCategory === null ? '' : activeCategory));
  }});
  applyFilters();
}});

// Mark "All" as active on load
(function() {{
  const allItem = document.querySelector('.sidebar-all');
  if (allItem) allItem.classList.add('active');
}})();

function escHtml(s) {{
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}}

function renderRow(p) {{
  const catColor = CAT_COLORS[p.taxonomy_category] || '#94a3b8';

  // Col 1: Severity badge
  const sevLabel = p.severity || 'Info';
  const sevHtml  = '<span class="sev-badge sev-' + escHtml(sevLabel) + '">'
                 + (sevLabel === 'High'   ? '🔴 High'
                  : sevLabel === 'Medium' ? '🟡 Medium'
                  : sevLabel === 'Low'    ? '🟢 Low'
                  :                         '⚪ Info')
                 + '</span>';

  // Col 2: Category pill
  const catHtml = '<span class="cat-pill" style="color:' + catColor
                + ';border-color:' + catColor + '40;background:' + catColor + '18"'
                + ' title="' + escHtml(p.taxonomy_category) + '">'
                + escHtml(p.taxonomy_category) + '</span>';

  // Col 3: Technique name (bold)
  const nameHtml = '<div class="tech-name">' + escHtml(p.technique_name) + '</div>';

  // Col 4: Persona/Role (italic, "—" if null)
  const personaHtml = p.persona_role
    ? '<span class="persona-tag">' + escHtml(p.persona_role) + '</span>'
    : '<span class="no-persona">\u2014</span>';

  // Col 5: Technique description (2 sentences max, no expand)
  const desc = (p.technique_description || '').trim();
  // Extract up to 2 sentences
  const sentences = desc.match(/[^.!?]*[.!?]/g) || [];
  const shortDesc = sentences.length >= 2
    ? sentences.slice(0, 2).join(' ').trim()
    : desc;
  const descHtml = '<div class="tech-desc">' + escHtml(shortDesc) + '</div>';

  // Col 6: Example prompt — terminal code block if has_actual_prompt, else "— no prompt extracted —"
  let promptHtml;
  if (p.has_actual_prompt && p.example_prompt) {{
    promptHtml = '<div class="prompt-block">' + escHtml(p.example_prompt) + '</div>';
  }} else {{
    promptHtml = '<span style="color:#555">\u2014 no prompt extracted \u2014</span>';
  }}

  // Col 7: Source — r/subreddit badge + ↗ link
  const subHtml = p.permalink
    ? '<a class="src-link" href="' + escHtml(p.permalink) + '" target="_blank" rel="noopener">'
    + '<span class="sub-badge">r/' + escHtml(p.subreddit) + '</span>'
    + '<span class="ext-icon"> &#8599;</span></a>'
    : '<span class="sub-badge">r/' + escHtml(p.subreddit) + '</span>';

  // Col 8: Date
  const dateStr  = (p.post_date || '').slice(0, 10);
  const dateHtml = '<span class="date-cell">' + escHtml(dateStr) + '</span>';

  return '<tr>'
    + '<td>' + sevHtml + '</td>'
    + '<td>' + catHtml + '</td>'
    + '<td style="max-width:220px">' + nameHtml + '</td>'
    + '<td>' + personaHtml + '</td>'
    + '<td style="max-width:240px">' + descHtml + '</td>'
    + '<td style="max-width:280px">' + promptHtml + '</td>'
    + '<td style="white-space:nowrap">' + subHtml + '</td>'
    + '<td>' + dateHtml + '</td>'
    + '</tr>';
}}

function getFiltered() {{
  const search = (document.getElementById('searchBox').value || '').toLowerCase();
  const catF   = document.getElementById('catFilter').value;
  const sevF   = document.getElementById('sevFilter').value;

  return DATA.filter(function(p) {{
    // Sidebar category
    if (activeCategory !== null && p.taxonomy_category !== activeCategory) return false;
    // Dropdown category
    if (catF && p.taxonomy_category !== catF) return false;
    // Severity
    if (sevF && p.severity !== sevF) return false;
    // Has Prompt toggle
    if (showHasPromptOnly && p.has_actual_prompt !== true) return false;
    // Search (technique_name, example_prompt, technique_description, title)
    if (search) {{
      const hay = [
        p.technique_name        || '',
        p.example_prompt        || '',
        p.technique_description || '',
        p.title                 || '',
        p.taxonomy_category     || '',
        p.persona_role          || '',
      ].join(' ').toLowerCase();
      if (!hay.includes(search)) return false;
    }}
    return true;
  }});
}}

function getSorted(data) {{
  return data.slice().sort(function(a, b) {{
    var av = a[sortCol];
    var bv = b[sortCol];
    // Null/undefined always sort last
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (sortCol === 'severity') {{
      av = SEV_ORDER[av] !== undefined ? SEV_ORDER[av] : 9;
      bv = SEV_ORDER[bv] !== undefined ? SEV_ORDER[bv] : 9;
    }}
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ?  1 : -1;
    return 0;
  }});
}}

function applyFilters() {{
  const filtered = getSorted(getFiltered());
  const tbody = document.getElementById('tableBody');
  const noRes = document.getElementById('noResults');

  if (filtered.length === 0) {{
    tbody.innerHTML = '';
    noRes.style.display = 'block';
  }} else {{
    noRes.style.display = 'none';
    tbody.innerHTML = filtered.map(renderRow).join('');
  }}
  document.getElementById('resultCount').textContent =
    'Showing ' + filtered.length + ' / ' + DATA.length;
}}

function sortTable(col) {{
  if (sortCol === col) {{
    sortDir = (sortDir === 'asc') ? 'desc' : 'asc';
  }} else {{
    sortCol = col;
    sortDir = 'asc';
  }}
  document.querySelectorAll('thead th').forEach(function(th) {{
    th.classList.toggle('sorted', th.dataset.col === col);
  }});
  applyFilters();
}}

function toggleHasPrompt() {{
  showHasPromptOnly = !showHasPromptOnly;
  const btn = document.getElementById('promptToggleBtn');
  btn.classList.toggle('prompt-active', showHasPromptOnly);
  btn.textContent = showHasPromptOnly ? 'Show All' : 'Has Prompt';
  applyFilters();
}}

function clearAllFilters() {{
  document.getElementById('searchBox').value = '';
  document.getElementById('catFilter').value = '';
  document.getElementById('sevFilter').value = '';
  activeCategory = null;
  showHasPromptOnly = false;
  document.getElementById('promptToggleBtn').textContent = 'Has Prompt';
  document.getElementById('promptToggleBtn').classList.remove('prompt-active');
  document.querySelectorAll('.sidebar-item').forEach(function(el) {{
    el.classList.toggle('active', el.dataset.cat === '');
  }});
  applyFilters();
}}

// Initial render
applyFilters();
</script>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(REPORTS_DIR, exist_ok=True)

    all_posts = load_db()
    print(f"Loaded {len(all_posts)} total posts from DB")

    relevant_posts = [p for p in all_posts if p.get("relevant") is True]
    print(f"Relevant posts (will appear in dashboard): {len(relevant_posts)}")

    if len(relevant_posts) == 0:
        print("WARNING: No relevant posts found — dashboard will be empty!", file=sys.stderr)

    html = build_html(all_posts)

    # Write desktop output
    with open(DESKTOP_OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Dashboard written to: {DESKTOP_OUTPUT}")

    # Write archive copy
    with open(ARCHIVE_OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Archived copy:        {ARCHIVE_OUTPUT}")

    # File size check
    size_bytes = os.path.getsize(DESKTOP_OUTPUT)
    print(f"File size:            {size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)")

    # Verification: parse embedded DATA variable
    with open(DESKTOP_OUTPUT, encoding="utf-8") as f:
        content = f.read()

    data_start = content.find('const DATA = ') + len('const DATA = ')
    data_end   = content.find('\nconst CAT_COLORS', data_start)
    data_str   = content[data_start:data_end].rstrip().rstrip(';')

    try:
        embedded = json.loads(data_str)
    except json.JSONDecodeError as e:
        print(f"ERROR: Embedded DATA is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nVerification:")
    print(f"  'has_actual_prompt' in HTML: {'has_actual_prompt' in content}")
    print(f"  Embedded DATA entries:       {len(embedded)}")

    # Print first 3 entries
    print(f"\nFirst 3 entries from embedded DATA:")
    for i, r in enumerate(embedded[:3]):
        print(f"\n  [{i}]")
        print(f"    technique_name:      {r.get('technique_name', '')!r}")
        print(f"    taxonomy_category:   {r.get('taxonomy_category', '')!r}")
        print(f"    severity:            {r.get('severity', '')!r}")
        print(f"    has_actual_prompt:   {r.get('has_actual_prompt')}")
        print(f"    persona_role:        {r.get('persona_role')!r}")
        prompt_preview = (r.get('example_prompt') or '')[:80]
        print(f"    example_prompt[0:80]:{prompt_preview!r}")


if __name__ == "__main__":
    main()
