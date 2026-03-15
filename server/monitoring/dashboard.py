"""
Professionelles Flask Dashboard für die zentrale Log-Datenbank
mit technischem, cleanem Design und Fokus auf Übersichtlichkeit.
"""
import json
import os
import sqlite3
from pathlib import Path
from flask import Flask, render_template_string, request
from datetime import datetime

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.getenv('SIGNING_AUDIT_DB', BASE_DIR / 'audit' / 'central_logs.db'))

HTML = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>Central Log Monitor</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@300;400;600;700&family=Source+Code+Pro:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base:       #fafafa;
            --bg-panel:      #ffffff;
            --bg-hover:      #f0f7ff;
            --bg-input:      #ffffff;
            --bg-header:     #1b1d1f;
            --border:        #d8dde6;
            --border-bright: #b0bac8;
            --text-primary:  #3b4151;
            --text-dim:      #6b7280;
            --text-muted:    #9ca3af;
            --accent:        #4990e2;
            --accent-dim:    rgba(73,144,226,0.1);
            --green:         #49cc90;
            --green-bg:      #f0fff4;
            --green-border:  #49cc90;
            --red:           #f93e3e;
            --red-bg:        #fff5f5;
            --amber:         #fca130;
            --amber-bg:      #fffbf0;
            --mono: 'Source Code Pro', 'Cascadia Code', monospace;
            --sans: 'Open Sans', system-ui, sans-serif;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }

        body {
            background: var(--bg-base);
            font-family: var(--sans);
            font-size: 14px;
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        /* ── Topbar — Swagger schwarz ── */
        .topbar {
            background: var(--bg-header);
            padding: 14px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 3px solid #89bf04;
        }

        .brand { display: flex; align-items: center; gap: 14px; }

        .brand-icon {
            width: 42px; height: 42px;
            border-radius: 6px;
            background: #89bf04;
            display: flex; align-items: center; justify-content: center;
            color: #fff;
            font-size: 20px;
        }

        .brand-text h1 {
            font-family: var(--sans);
            font-size: 22px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.01em;
        }

        .brand-text .tagline {
            font-size: 11px;
            color: #9ca3af;
            margin-top: 1px;
            font-family: var(--mono);
        }

        .status-pill {
            display: flex; align-items: center; gap: 7px;
            padding: 5px 14px;
            background: rgba(137,191,4,0.15);
            border: 1px solid #89bf04;
            border-radius: 20px;
            font-size: 11px;
            color: #89bf04;
            font-weight: 700;
            letter-spacing: 0.08em;
        }

        .status-dot {
            width: 7px; height: 7px;
            border-radius: 50%;
            background: #89bf04;
            box-shadow: 0 0 6px #89bf04;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

        /* ── Shell ── */
        .shell {
            max-width: 1400px;
            margin: 0 auto;
            padding: 28px 32px;
        }

        /* ── Stat Cards — Swagger-Sektions-Style ── */
        .stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-bottom: 24px;
        }

        .stat {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px 20px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            transition: box-shadow 0.2s;
        }

        .stat:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.12); }

        .stat::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            border-radius: 6px 6px 0 0;
        }

        .stat.green { border-left: 4px solid var(--green); border-top: none; }
        .stat.green::before { display: none; }
        .stat.green .stat-label { color: #166534; }
        .stat.green .stat-value { color: #15803d; }
        .stat.green .stat-sub   { color: #4ade80; }
        .stat.green { background: linear-gradient(135deg, #f0fdf4, #fff); }

        .stat.blue { border-left: 4px solid var(--accent); }
        .stat.blue::before { display: none; }
        .stat.blue .stat-label { color: #1e40af; }
        .stat.blue .stat-value { color: #1d4ed8; }
        .stat.blue .stat-sub   { color: #60a5fa; }
        .stat.blue { background: linear-gradient(135deg, #eff6ff, #fff); }

        .stat.cyan { border-left: 4px solid #0891b2; }
        .stat.cyan::before { display: none; }
        .stat.cyan .stat-label { color: #155e75; }
        .stat.cyan .stat-value { color: #0e7490; }
        .stat.cyan .stat-sub   { color: #22d3ee; }
        .stat.cyan { background: linear-gradient(135deg, #ecfeff, #fff); }

        .stat.amber { border-left: 4px solid var(--amber); }
        .stat.amber::before { display: none; }
        .stat.amber .stat-label { color: #92400e; }
        .stat.amber .stat-value { color: #b45309; font-size: 14px; letter-spacing: 0; }
        .stat.amber .stat-sub   { color: #fbbf24; }
        .stat.amber { background: linear-gradient(135deg, #fffbeb, #fff); }

        .stat-label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 30px;
            font-weight: 700;
            line-height: 1;
            letter-spacing: -0.02em;
            font-family: var(--sans);
        }

        .stat-sub { font-size: 12px; margin-top: 5px; font-weight: 500; }

        /* ── Filter Panel — Swagger info-box Style ── */
        .filter-panel {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 18px 22px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }

        .filter-header {
            display: flex; align-items: center; gap: 8px;
            font-size: 11px; font-weight: 700;
            color: var(--text-dim);
            text-transform: uppercase; letter-spacing: 0.1em;
            margin-bottom: 14px; padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }

        .filter-header i { color: var(--accent); }

        .filter-grid {
            display: grid;
            grid-template-columns: 1.2fr 1.4fr 1.6fr 1.4fr auto auto;
            gap: 12px;
            align-items: end;
        }

        .field-label {
            font-size: 11px; font-weight: 700;
            color: var(--text-dim);
            text-transform: uppercase; letter-spacing: 0.06em;
            margin-bottom: 5px;
        }

        .field-label i { margin-right: 4px; }

        input[type="text"],
        input[type="datetime-local"],
        select {
            width: 100%;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text-primary);
            font-family: var(--mono);
            font-size: 12px;
            padding: 7px 10px;
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }

        input[type="text"]::placeholder { color: var(--text-muted); }

        input[type="text"]:focus,
        input[type="datetime-local"]:focus,
        select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(73,144,226,0.15);
        }

        .btn-filter {
            background: #89bf04;
            border: none; border-radius: 4px;
            color: #fff;
            font-family: var(--sans);
            font-size: 13px; font-weight: 700;
            padding: 7px 18px; cursor: pointer;
            white-space: nowrap;
            transition: background 0.15s;
            display: flex; align-items: center; gap: 6px;
        }

        .btn-filter:hover { background: #6ea303; }

        .btn-reset {
            background: transparent;
            border: 1px solid var(--border-bright);
            border-radius: 4px;
            color: var(--text-dim);
            font-family: var(--sans);
            font-size: 13px; font-weight: 600;
            padding: 7px 14px; cursor: pointer;
            transition: border-color 0.15s, color 0.15s;
            white-space: nowrap; text-decoration: none;
            display: flex; align-items: center; gap: 5px;
        }

        .btn-reset:hover { border-color: var(--red); color: var(--red); }

        .active-chips {
            display: flex; flex-wrap: wrap; gap: 6px;
            margin-top: 12px; padding-top: 10px;
            border-top: 1px solid var(--border);
        }

        .chip {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 3px 10px;
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 20px;
            font-size: 11px; font-weight: 600;
            color: #1d4ed8;
        }

        /* ── Table — Swagger opblock style ── */
        .table-wrap {
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }

        .tbl-header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 12px 20px;
            border-bottom: 2px solid var(--border);
            background: #f7f9fb;
        }

        .tbl-title {
            font-size: 13px; font-weight: 700;
            color: var(--text-primary);
            text-transform: uppercase; letter-spacing: 0.05em;
            display: flex; align-items: center; gap: 8px;
        }

        .tbl-title i { color: var(--accent); }
        .tbl-count { font-size: 12px; color: var(--text-muted); font-weight: 600; }

        table { width: 100%; border-collapse: collapse; }

        thead th {
            background: #f7f9fb;
            color: #6b7280;
            font-family: var(--sans);
            font-size: 11px; font-weight: 700;
            text-transform: uppercase; letter-spacing: 0.08em;
            padding: 10px 16px;
            border-bottom: 2px solid #e5e9f0;
            white-space: nowrap;
            user-select: none;
        }

        tbody tr { border-bottom: 1px solid #eef1f6; transition: background 0.1s; }
        tbody tr:last-child { border-bottom: none; }
        tbody tr:hover { background: #f0f7ff; }

        td {
            padding: 11px 16px;
            vertical-align: middle;
            font-size: 13px;
            color: var(--text-primary);
        }

        .ts-date { color: #1e293b; font-size: 13px; font-weight: 600; font-family: var(--mono); }
        .ts-time { color: #64748b; font-size: 12px; font-family: var(--mono); }

        .client-id {
            color: #1d4ed8; font-weight: 700;
            font-family: var(--mono); font-size: 13px;
        }

        .host { color: #4b5563; font-size: 13px; font-family: var(--mono); }

        /* ── Event tags — wie Swagger Method-Badges ── */
        .ev-tag {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 11px; font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            min-width: 80px;
            text-align: center;
            font-family: var(--sans);
        }

        .ev-tag.sig  { background: #61affe; color: #fff; }
        .ev-tag.exec { background: #49cc90; color: #fff; }
        .ev-tag.unk  { background: #9ca3af; color: #fff; }

        .fp {
            max-width: 300px; overflow: hidden;
            text-overflow: ellipsis; white-space: nowrap;
            color: #374151; font-size: 13px;
            font-family: var(--mono); cursor: default;
        }

        /* Signature badges */
        .badge-valid   { display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:3px;font-size:12px;font-weight:700;background:#49cc90;color:#fff; }
        .badge-invalid { display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:3px;font-size:12px;font-weight:700;background:#f93e3e;color:#fff; }
        .badge-na      { display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:3px;font-size:12px;font-weight:700;background:#e5e7eb;color:#6b7280; }

        .exit-ok  { color: #15803d; font-weight: 700; font-family: var(--mono); font-size: 14px; }
        .exit-err { color: #dc2626; font-weight: 700; font-family: var(--mono); font-size: 14px; }
        .exit-na  { color: #9ca3af; font-family: var(--mono); }

        /* ── Pagination ── */
        .pagination-bar {
            display: flex; align-items: center; justify-content: space-between;
            padding: 12px 20px;
            border-top: 1px solid var(--border);
            background: #f7f9fb;
        }

        .pg-info { font-size: 12px; color: var(--text-dim); font-weight: 500; }
        .pg-nav { display: flex; gap: 4px; }

        .pg-btn {
            display: inline-flex; align-items: center; justify-content: center;
            min-width: 32px; height: 30px; padding: 0 8px;
            border-radius: 4px;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--text-primary);
            font-family: var(--sans); font-size: 12px; font-weight: 600;
            text-decoration: none;
            transition: all 0.15s;
        }

        .pg-btn:hover { border-color: var(--accent); color: var(--accent); background: var(--accent-dim); }
        .pg-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
        .pg-btn.disabled { opacity: 0.4; pointer-events: none; }

        /* ── Empty state ── */
        .empty { padding: 64px 20px; text-align: center; color: var(--text-muted); }
        .empty i { font-size: 32px; display: block; margin-bottom: 12px; opacity: 0.4; color: var(--accent); }
        .empty p { font-size: 13px; }

        /* ── Footer ── */
        .footer {
            display: flex; align-items: center; justify-content: flex-end;
            gap: 16px; margin-top: 16px;
            font-size: 11px; color: var(--text-muted);
            font-family: var(--mono);
        }

        .footer span { display: flex; align-items: center; gap: 5px; }

        /* ── Refresh button ── */
        .btn-refresh {
            display: flex; align-items: center; gap: 6px;
            padding: 6px 14px;
            background: rgba(137,191,4,0.1);
            border: 1px solid #89bf04;
            border-radius: 4px;
            color: #5a8600;
            font-size: 12px; font-weight: 700;
            text-decoration: none;
            transition: all 0.15s;
            font-family: var(--sans);
        }

        .btn-refresh:hover { background: rgba(137,191,4,0.2); }

        /* ── Responsive ── */
        @media (max-width: 1280px) {
            .stats-row { grid-template-columns: repeat(2, 1fr); }
            .filter-grid { grid-template-columns: 1fr 1fr 1fr; }
        }

        @media (max-width: 768px) {
            .shell { padding: 14px; }
            .filter-grid { grid-template-columns: 1fr 1fr; }
            .stats-row { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>

    <!-- ── Topbar — ausserhalb des shell, volle Breite wie Swagger ── -->
    <div class="topbar">
        <div class="brand">
            <div class="brand-icon"><i class="bi bi-hdd-stack"></i></div>
            <div class="brand-text">
                <h1>central-log-monitor</h1>
                <div class="tagline">{{ db_size }} MB · {{ total_entries }} Einträge · aktualisiert {{ now.strftime('%H:%M:%S') }}</div>
            </div>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
            <div style="font-size:11px;color:#9ca3af;font-family:var(--mono);">
                auto-refresh in <span id="countdown" style="color:#89bf04;font-weight:700;">30</span>s
            </div>
            <a href="{{ request.url }}" class="btn-refresh">
                <i class="bi bi-arrow-clockwise"></i> Refresh
            </a>
            <div class="status-pill">
                <div class="status-dot"></div>
                LIVE
            </div>
        </div>
    </div>

<div class="shell">

    <!-- ── Stats ── -->
    <div class="stats-row">
        <div class="stat green">
            <div class="stat-label"><i class="bi bi-shield-check me-1"></i>Gültige Signaturen</div>
            <div class="stat-value">{{ stats.valid_signatures }}</div>
            <div class="stat-sub">{{ stats.invalid_signatures }} ungültig</div>
        </div>
        <div class="stat blue">
            <div class="stat-label"><i class="bi bi-activity me-1"></i>Events gesamt</div>
            <div class="stat-value">{{ stats.total_events }}</div>
            <div class="stat-sub">{{ stats.unique_clients }} aktive Clients</div>
        </div>
        <div class="stat cyan">
            <div class="stat-label"><i class="bi bi-terminal me-1"></i>Exit OK</div>
            <div class="stat-value">{{ stats.success_exits }}</div>
            <div class="stat-sub">{{ stats.error_exits }} Fehler</div>
        </div>
        <div class="stat amber">
            <div class="stat-label"><i class="bi bi-calendar-range me-1"></i>Zeitraum</div>
            <div class="stat-value" style="font-size:14px;letter-spacing:0;">{{ stats.time_range }}</div>
        </div>
    </div>

    <!-- ── Filter ── -->
    <div class="filter-panel">
        <div class="filter-header">
            <i class="bi bi-funnel"></i> Filter
        </div>
        <form method="get">
            <div class="filter-grid">
                <div>
                    <div class="field-label"><i class="bi bi-person-badge"></i>Client-ID</div>
                    <input type="text" name="client_id" value="{{ client_id or '' }}" placeholder="z.B. opensuse">
                </div>
                <div>
                    <div class="field-label"><i class="bi bi-tag"></i>Event-Type</div>
                    <select name="event_type">
                        <option value="">— alle —</option>
                        <option value="signature_verification" {% if event_type == 'signature_verification' %}selected{% endif %}>signature_verification</option>
                        <option value="file_execution" {% if event_type == 'file_execution' %}selected{% endif %}>file_execution</option>
                    </select>
                </div>
                <div>
                    <div class="field-label"><i class="bi bi-clock"></i>Ab Datum</div>
                    <input type="datetime-local" name="start_date" value="{{ start_date or '' }}">
                </div>
                <div>
                    <div class="field-label"><i class="bi bi-file-code"></i>Datei (enthält)</div>
                    <input type="text" name="file_path" value="{{ file_path or '' }}" placeholder="z.B. testfile">
                </div>
                <div style="display:flex;gap:6px;align-items:flex-end;">
                    <div style="flex:1;">
                        <div class="field-label">Pro Seite</div>
                        <select name="per_page" onchange="this.form.submit()">
                            <option value="20"  {% if per_page == 20  %}selected{% endif %}>20</option>
                            <option value="50"  {% if per_page == 50  %}selected{% endif %}>50</option>
                            <option value="100" {% if per_page == 100 %}selected{% endif %}>100</option>
                        </select>
                    </div>
                </div>
                <div style="display:flex;gap:6px;align-items:flex-end;padding-top:0;">
                    <button type="submit" class="btn-filter"><i class="bi bi-funnel-fill"></i>Anwenden</button>
                    <a href="?" class="btn-reset"><i class="bi bi-x-lg"></i>Reset</a>
                </div>
            </div>

            {% if client_id or event_type or start_date or file_path %}
            <div class="active-chips">
                {% if client_id %}<span class="chip"><i class="bi bi-person-badge"></i>{{ client_id }}</span>{% endif %}
                {% if event_type %}<span class="chip"><i class="bi bi-tag"></i>{{ event_type }}</span>{% endif %}
                {% if start_date %}<span class="chip"><i class="bi bi-clock"></i>ab {{ start_date[:10] }}</span>{% endif %}
                {% if file_path %}<span class="chip"><i class="bi bi-file-code"></i>{{ file_path }}</span>{% endif %}
            </div>
            {% endif %}
        </form>
    </div>

    <!-- ── Table ── -->
    <div class="table-wrap">
        <div class="tbl-header">
            <div class="tbl-title"><i class="bi bi-table"></i>Log-Einträge</div>
            <div class="tbl-count">{{ total_entries }} Treffer</div>
        </div>

        {% if rows %}
        <table>
            <thead>
                <tr>
                    <th>Zeitstempel</th>
                    <th>Client</th>
                    <th>Host</th>
                    <th>Event</th>
                    <th>Datei</th>
                    <th>Signatur</th>
                    <th>Exit</th>
                </tr>
            </thead>
            <tbody>
                {% for row in rows %}
                <tr>
                    <td>
                        <div class="ts-date">{{ row['received_at'][:10] }}</div>
                        <div class="ts-time">{{ row['received_at'][11:19] }}</div>
                    </td>
                    <td><span class="client-id">{{ row['client_id'] }}</span></td>
                    <td><span class="host">{{ row['hostname'] }}</span></td>
                    <td>
                        {% if row['event_type'] == 'signature_verification' %}
                            <span class="ev-tag sig">sig_verify</span>
                        {% elif row['event_type'] == 'file_execution' %}
                            <span class="ev-tag exec">file_exec</span>
                        {% else %}
                            <span class="ev-tag unk">{{ row['event_type'] or 'unknown' }}</span>
                        {% endif %}
                    </td>
                    <td>
                        <div class="fp" title="{{ row['file_path'] }}">{{ row['file_path'] or '—' }}</div>
                    </td>
                    <td>
                        {% if row['signature_valid'] == true %}
                            <span class="badge-valid"><i class="bi bi-check-circle-fill"></i>valid</span>
                        {% elif row['signature_valid'] == false %}
                            <span class="badge-invalid"><i class="bi bi-x-circle-fill"></i>invalid</span>
                        {% else %}
                            <span class="badge-na"><i class="bi bi-dash-circle"></i>n/a</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if row['exit_code'] == 0 %}
                            <span class="exit-ok">{{ row['exit_code'] }}</span>
                        {% elif row['exit_code'] %}
                            <span class="exit-err">{{ row['exit_code'] }}</span>
                        {% else %}
                            <span class="exit-na">—</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <!-- Pagination -->
        <div class="pagination-bar">
            <div class="pg-info">
                Zeige {{ ((page-1) * per_page) + 1 }}–{{ [page * per_page, total_entries]|min }}
                von {{ total_entries }} Einträgen
            </div>
            <div class="pg-nav">
                <a class="pg-btn {% if page <= 1 %}disabled{% endif %}"
                   href="?{% for k, v in request.args.items() if k != 'page' %}{{ k }}={{ v }}&{% endfor %}page=1">«</a>
                <a class="pg-btn {% if page <= 1 %}disabled{% endif %}"
                   href="?{% for k, v in request.args.items() if k != 'page' %}{{ k }}={{ v }}&{% endfor %}page={{ page - 1 }}">‹</a>

                {% for p in range([1, page-2]|max, [total_pages, page+3]|min) %}
                    <a class="pg-btn {% if p == page %}active{% endif %}"
                       href="?{% for k, v in request.args.items() if k != 'page' %}{{ k }}={{ v }}&{% endfor %}page={{ p }}">{{ p }}</a>
                {% endfor %}

                <a class="pg-btn {% if page >= total_pages %}disabled{% endif %}"
                   href="?{% for k, v in request.args.items() if k != 'page' %}{{ k }}={{ v }}&{% endfor %}page={{ page + 1 }}">›</a>
                <a class="pg-btn {% if page >= total_pages %}disabled{% endif %}"
                   href="?{% for k, v in request.args.items() if k != 'page' %}{{ k }}={{ v }}&{% endfor %}page={{ total_pages }}">»</a>
            </div>
        </div>

        {% else %}
        <div class="empty">
            <i class="bi bi-inbox"></i>
            <p>Keine Einträge gefunden.</p>
            <p style="margin-top:8px;"><a href="?" class="btn-reset" style="display:inline-flex;">Filter zurücksetzen</a></p>
        </div>
        {% endif %}
    </div>

    <!-- ── Footer ── -->
    <div class="footer">
        <span><i class="bi bi-hdd me-1"></i>{{ db_size }} MB</span>
        <span><i class="bi bi-layers me-1"></i>{{ tablespace }} tables</span>
        <span><i class="bi bi-clock me-1"></i>{{ now.strftime('%d.%m.%Y %H:%M:%S') }}</span>
    </div>

</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    let s = 30;
    const el = document.getElementById('countdown');
    setInterval(() => { if (el && s > 0) el.textContent = --s; }, 1000);
</script>
</body>
</html>
"""

def parse(db_row):
    try:
        d = json.loads(db_row['data'])
    except Exception:
        d = {}
    return {
        'received_at': db_row['received_at'],
        'client_id': db_row['client_id'],
        'hostname': db_row['hostname'],
        'event_type': d.get('event_type'),
        'file_path': d.get('file_path'),
        'signature_valid': d.get('signature_valid'),
        'exit_code': d.get('exit_code')
    }

@app.route('/')
def dashboard():
    client_id  = request.args.get('client_id')
    event_type = request.args.get('event_type')
    file_path  = request.args.get('file_path')
    start_date = request.args.get('start_date')
    page       = int(request.args.get('page', 1))
    per_page   = int(request.args.get('per_page', 20))

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        q      = 'SELECT COUNT(*) FROM client_logs WHERE 1=1'
        params = []

        if client_id:
            q += ' AND client_id = ?';               params.append(client_id)
        if event_type:
            q += ' AND json_extract(data, "$.event_type") = ?'; params.append(event_type)
        if file_path:
            q += ' AND json_extract(data, "$.file_path") LIKE ?'; params.append(f'%{file_path}%')
        if start_date:
            q += ' AND received_at >= ?';             params.append(start_date)

        total_entries = conn.execute(q, params).fetchone()[0]

        stats_row = conn.execute("""
            SELECT
                COUNT(CASE WHEN json_extract(data,'$.signature_valid')=1 THEN 1 END) as valid_signatures,
                COUNT(CASE WHEN json_extract(data,'$.signature_valid')=0 THEN 1 END) as invalid_signatures,
                COUNT(DISTINCT client_id)                                             as unique_clients,
                COUNT(CASE WHEN json_extract(data,'$.exit_code')=0 THEN 1 END)       as success_exits,
                COUNT(CASE WHEN json_extract(data,'$.exit_code')>0 THEN 1 END)       as error_exits,
                COUNT(*)                                                               as total_events,
                MIN(received_at)                                                       as first_event,
                MAX(received_at)                                                       as last_event
            FROM client_logs
        """).fetchone()
        stats = dict(stats_row)

        if stats['first_event'] and stats['last_event']:
            time_range = f"{stats['first_event'][:10]} – {stats['last_event'][:10]}"
        else:
            time_range = "—"

        data_q = q.replace('COUNT(*)', '*') + ' ORDER BY received_at DESC LIMIT ? OFFSET ?'
        rows   = [parse(r) for r in conn.execute(data_q, params + [per_page, (page-1)*per_page]).fetchall()]

        total_pages = max(1, (total_entries + per_page - 1) // per_page)
        db_size     = round(os.path.getsize(DB_PATH) / (1024 * 1024), 2)

    return render_template_string(
        HTML,
        rows=rows,
        client_id=client_id, event_type=event_type,
        file_path=file_path,  start_date=start_date,
        page=page, per_page=per_page,
        total_pages=total_pages, total_entries=total_entries,
        stats={
            'valid_signatures':   stats['valid_signatures']   or 0,
            'invalid_signatures': stats['invalid_signatures'] or 0,
            'unique_clients':     stats['unique_clients']     or 0,
            'total_events':       stats['total_events']       or 0,
            'success_exits':      stats['success_exits']      or 0,
            'error_exits':        stats['error_exits']        or 0,
            'time_range':         time_range,
        },
        now=datetime.now(),
        db_size=db_size,
        tablespace='main',
        request=request,
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)