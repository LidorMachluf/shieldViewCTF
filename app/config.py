import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.environ.get('SHIELDVIEW_DATA_DIR', os.path.join(os.path.dirname(BASE_DIR), 'data'))
LOGS_DIR = os.path.join(DATA_DIR, 'logs')

DATABASE_PATH = os.path.join(DATA_DIR, 'shieldview.db')
AUDIT_LOG_PATH = os.path.join(DATA_DIR, 'audit.log')

SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'shieldview-dev-key-not-for-production')

WEBHOOK_URL = os.environ.get('SHIELDVIEW_WEBHOOK_URL', '')
WEBHOOK_ENABLED = bool(WEBHOOK_URL)
WEBHOOK_BATCH_SIZE = 10
WEBHOOK_FLUSH_INTERVAL = 5

MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB

# Default analyst team — new candidates see this analyst's alerts on the dashboard
DEFAULT_TEAM_ANALYST_ID = 2  # analyst1 (James Wilson)

# CTF Flags — each vulnerability has a unique flag
FLAGS = {
    "sqli":           "FLAG{sql_1nj3ct10n_m4st3r}",
    "idor_alerts":    "FLAG{1d0r_al3rt_hunt3r}",
    "xss":            "FLAG{r3fl3ct3d_xss_pr0}",
    "cookie_tamper":  "FLAG{c00k13_m0nst3r_adm1n}",
    "debug_endpoint": "FLAG{d3bug_3ndp01nt_l34k}",
    "hardcoded_key":  "FLAG{h4rdc0d3d_s3cr3ts}",
    "profile_idor":   "FLAG{pr0f1l3_1d0r_f0und}",
    "open_redirect":  "FLAG{0p3n_r3d1r3ct_vuln}",
    "path_traversal": "FLAG{p4th_tr4v3rs4l_pr0}",
    "stored_xss":     "FLAG{st0r3d_xss_p3rs1st}",
}
