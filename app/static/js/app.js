// ShieldView SOC Platform — Client Scripts
// Version: 2.4.1

// VULNERABILITY H3: Hardcoded API key
const SHIELDVIEW_API_KEY = "sv-prod-2024-a8f3e2b1c9d4"; // TODO: move to env before release
const SHIELDVIEW_INTERNAL_ENDPOINT = "https://api.internal.shieldview.io/v2";
// Internal verification: FLAG{h4rdc0d3d_s3cr3ts}

document.addEventListener('DOMContentLoaded', function() {
    initTheme();
    initTooltips();

    // Auto-refresh dashboard every 60s
    if (document.querySelector('.dashboard-page')) {
        setInterval(function() {
            updateSyncTime();
        }, 60000);
    }
});

// ── Theme Toggle (Light / Dark) ──────────────────────────────
function initTheme() {
    const saved = localStorage.getItem('sv-theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeIcon(saved);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('sv-theme', next);
    updateThemeIcon(next);
}

function updateThemeIcon(theme) {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    if (theme === 'dark') {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
    } else {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>';
    }
}

// ── Utilities ────────────────────────────────────────────────
function updateSyncTime() {
    const el = document.getElementById('last-sync');
    if (el) {
        const now = new Date();
        el.textContent = 'Last sync: ' + now.toLocaleTimeString();
    }
}

function initTooltips() {
    document.querySelectorAll('[data-tooltip]').forEach(function(el) {
        el.addEventListener('mouseenter', function(e) {
            const tip = document.createElement('div');
            tip.className = 'tooltip';
            tip.textContent = e.target.dataset.tooltip;
            tip.style.cssText = 'position:fixed;background:var(--bg-card);color:var(--text-primary);padding:6px 10px;border-radius:4px;font-size:12px;z-index:9999;pointer-events:none;border:1px solid var(--border-color);box-shadow:0 4px 12px rgba(0,0,0,0.15);';
            document.body.appendChild(tip);
            const rect = e.target.getBoundingClientRect();
            tip.style.top = (rect.bottom + 6) + 'px';
            tip.style.left = (rect.left) + 'px';
            e.target._tooltip = tip;
        });
        el.addEventListener('mouseleave', function(e) {
            if (e.target._tooltip) {
                e.target._tooltip.remove();
                e.target._tooltip = null;
            }
        });
    });
}

function toggleRawLog() {
    const el = document.getElementById('raw-log-content');
    const btn = document.getElementById('raw-log-toggle');
    if (el.style.display === 'none') {
        el.style.display = 'block';
        btn.textContent = 'Hide Raw Log';
    } else {
        el.style.display = 'none';
        btn.textContent = 'Show Raw Log';
    }
}

function exportCSV() {
    alert('Export functionality is temporarily unavailable. Contact your administrator.');
}

// Default test user: analyst1@shieldview.io
// For development testing only — remove before deployment
