import sqlite3
import os
import json
from datetime import datetime, timedelta
import random

from app.config import DATABASE_PATH, DATA_DIR, LOGS_DIR, FLAGS
from app.db import init_db

SEED_USERS = [
    {
        "email": "admin@shieldview.io",
        "password": "Sv$ecure#Adm1n!",
        "display_name": "Sarah Chen",
        "role": "admin",
        "is_seed": 1,
    },
    {
        "email": "analyst1@shieldview.io",
        "password": "An@lyst!2024",
        "display_name": "James Wilson",
        "role": "user",
        "is_seed": 1,
    },
    {
        "email": "analyst2@shieldview.io",
        "password": "V!ewer#Sec2024",
        "display_name": "Maya Rodriguez",
        "role": "user",
        "is_seed": 1,
    },
]

# ──────────────────────────────────────────────────────────────────────
# ALERTS: 10 assigned to analyst1 (shown on dashboard), 10 to analyst2,
# 10 to admin (hidden — discoverable only via IDOR)
# ──────────────────────────────────────────────────────────────────────

# Team Alpha alerts — assigned to analyst1 (user_id=2) — visible on dashboard
TEAM_ALPHA_ALERTS = [
    {
        "title": "Suspicious process execution detected on prod-web-03",
        "description": "Process 'mimikatz.exe' was executed by user 'svc-backup' on host prod-web-03. This binary is commonly associated with credential harvesting attacks. The process was spawned from cmd.exe with parent PID 4012.",
        "severity": "HIGH",
        "asset_hostname": "prod-web-03.shieldview.internal",
        "asset_ip": "10.0.3.15",
        "source_ip": "10.0.5.22",
        "raw_log": '{"timestamp":"2024-12-10T14:32:01Z","level":"CRITICAL","source":"endpoint-agent","host":"prod-web-03","pid":8841,"parent_pid":4012,"process":"mimikatz.exe","user":"svc-backup","action":"process_create","hash":"a4b35de71b20..."}',
    },
    {
        "title": "Brute force attempt on SSH (prod-db-01)",
        "description": "Detected 847 failed SSH login attempts from external IP 203.0.113.89 targeting host prod-db-01 within a 5-minute window. The attempts used common username wordlists including root, admin, and ubuntu.",
        "severity": "HIGH",
        "asset_hostname": "prod-db-01.shieldview.internal",
        "asset_ip": "10.0.2.50",
        "source_ip": "203.0.113.89",
        "raw_log": '{"timestamp":"2024-12-11T03:15:22Z","level":"ALERT","source":"ids","rule":"ssh-brute-force","src_ip":"203.0.113.89","dst_ip":"10.0.2.50","dst_port":22,"attempts":847,"window":"300s","usernames":["root","admin","ubuntu","deploy"]}',
    },
    {
        "title": "Unusual outbound DNS query to Tor exit node",
        "description": "DNS resolver logged a query for a known Tor exit node relay address from internal host 10.0.10.15. While Tor usage may be legitimate, it is against company policy and warrants investigation.",
        "severity": "MEDIUM",
        "asset_hostname": "analyst-ws-01.shieldview.internal",
        "asset_ip": "10.0.10.15",
        "source_ip": "10.0.10.15",
        "raw_log": '{"timestamp":"2024-12-10T10:22:45Z","level":"WARNING","source":"dns-monitor","query":"relay.tor-exit-node.net","query_type":"A","src_ip":"10.0.10.15","resolver":"10.0.1.2"}',
    },
    {
        "title": "Failed login spike from single IP",
        "description": "47 failed login attempts detected within 2 minutes from IP 203.0.113.89 against the VPN gateway. Targeted accounts include multiple analyst and admin usernames. Rate limiting has been triggered.",
        "severity": "MEDIUM",
        "asset_hostname": "vpn-gw-01.shieldview.internal",
        "asset_ip": "10.0.0.5",
        "source_ip": "203.0.113.89",
        "raw_log": '{"timestamp":"2024-12-12T08:14:30Z","level":"WARNING","source":"vpn","event":"auth_failure_spike","src_ip":"203.0.113.89","attempts":47,"window":"120s","targeted_users":["s.chen","j.wilson","m.rodriguez","admin"]}',
    },
    {
        "title": "Port scan detected from internal host",
        "description": "Network detection system identified a TCP SYN scan originating from 10.0.5.22 targeting the 10.0.2.0/24 subnet. 1,024 ports were scanned across 15 hosts in a sequential pattern consistent with automated reconnaissance.",
        "severity": "MEDIUM",
        "asset_hostname": "dev-tools-01.shieldview.internal",
        "asset_ip": "10.0.5.22",
        "source_ip": "10.0.5.22",
        "raw_log": '{"timestamp":"2024-12-10T15:48:12Z","level":"WARNING","source":"ndr","detection":"port-scan","src_ip":"10.0.5.22","dst_subnet":"10.0.2.0/24","ports_scanned":1024,"hosts_targeted":15,"scan_type":"TCP-SYN"}',
    },
    {
        "title": "Sensitive file accessed outside business hours",
        "description": "User 'j.wilson' accessed file '/shared/finance/Q4-2024-revenue.xlsx' at 02:47 AM local time. This user's normal working hours are 08:00-18:00. The file is classified as 'Confidential - Financial'.",
        "severity": "MEDIUM",
        "asset_hostname": "prod-file-01.shieldview.internal",
        "asset_ip": "10.0.2.80",
        "source_ip": "10.0.10.33",
        "raw_log": '{"timestamp":"2024-12-14T00:47:22Z","level":"WARNING","source":"dlp","event":"sensitive_access","user":"j.wilson","file":"/shared/finance/Q4-2024-revenue.xlsx","classification":"confidential-financial","local_time":"02:47","normal_hours":"08:00-18:00"}',
    },
    {
        "title": "Routine vulnerability scan completed",
        "description": "Scheduled weekly vulnerability scan of the 10.0.3.0/24 subnet completed. Found 23 informational findings, 8 low-severity findings, and 2 medium-severity findings. No critical or high findings detected.",
        "severity": "LOW",
        "asset_hostname": "vuln-scanner-01.shieldview.internal",
        "asset_ip": "10.0.1.100",
        "source_ip": "10.0.1.100",
        "raw_log": '{"timestamp":"2024-12-10T06:00:15Z","level":"INFO","source":"vuln-scanner","scan_id":"VS-2024-1210","subnet":"10.0.3.0/24","findings":{"critical":0,"high":0,"medium":2,"low":8,"info":23},"duration":"42m"}',
    },
    {
        "title": "SSL certificate expiring in 14 days",
        "description": "The TLS certificate for 'api.shieldview.io' expires on 2024-12-28. Auto-renewal is configured but should be verified. Certificate is issued by Let's Encrypt with SHA-256 RSA signature.",
        "severity": "LOW",
        "asset_hostname": "api.shieldview.io",
        "asset_ip": "34.120.50.11",
        "source_ip": "10.0.1.100",
        "raw_log": '{"timestamp":"2024-12-14T08:00:00Z","level":"INFO","source":"cert-monitor","domain":"api.shieldview.io","expires":"2024-12-28T00:00:00Z","issuer":"LetsEncrypt","auto_renew":true,"algo":"SHA256-RSA"}',
    },
    {
        "title": "New device enrolled in MDM",
        "description": "A new MacBook Pro (serial: C02FN3XXMD6T) was enrolled in the MDM system by user 'j.wilson'. Device has been assigned the 'analyst-standard' profile with full disk encryption and endpoint agent.",
        "severity": "LOW",
        "asset_hostname": "C02FN3XXMD6T",
        "asset_ip": "10.0.10.70",
        "source_ip": "10.0.10.70",
        "raw_log": '{"timestamp":"2024-12-09T09:15:30Z","level":"INFO","source":"mdm","event":"device_enrolled","serial":"C02FN3XXMD6T","model":"MacBook Pro 16","user":"j.wilson","profile":"analyst-standard","fde":true}',
    },
    {
        "title": "EDR agent updated on workstation fleet",
        "description": "Endpoint detection and response agent updated from v4.2.1 to v4.3.0 on 42 out of 45 workstations. 3 workstations are offline and will be updated when they reconnect. No issues reported during rollout.",
        "severity": "LOW",
        "asset_hostname": "edr-console.shieldview.internal",
        "asset_ip": "10.0.1.30",
        "source_ip": "10.0.1.30",
        "raw_log": '{"timestamp":"2024-12-12T05:30:00Z","level":"INFO","source":"edr-console","event":"agent_update","from_version":"4.2.1","to_version":"4.3.0","updated":42,"total":45,"pending":3}',
    },
]

# Team Beta alerts — assigned to analyst2 (user_id=3) — hidden from dashboard
TEAM_BETA_ALERTS = [
    {
        "title": "Unauthorized S3 bucket policy change",
        "description": "S3 bucket 'shieldview-prod-backups' ACL was modified to allow public read access by IAM user 'deploy-bot'. This change was not part of any approved change request and exposes backup data to the internet.",
        "severity": "HIGH",
        "asset_hostname": "s3.amazonaws.com",
        "asset_ip": "52.216.100.35",
        "source_ip": "198.51.100.14",
        "raw_log": '{"timestamp":"2024-12-12T09:45:11Z","level":"CRITICAL","source":"cloudtrail","event":"PutBucketAcl","bucket":"shieldview-prod-backups","principal":"arn:aws:iam::123456789:user/deploy-bot","new_acl":"public-read","region":"us-east-1"}',
    },
    {
        "title": "Privilege escalation via sudo on analyst-ws-03",
        "description": "User 'j.wilson' executed 'sudo su -' and gained root access on analyst-ws-03. This user does not have sudo privileges in the approved access matrix. Investigation needed to determine how sudo access was obtained.",
        "severity": "HIGH",
        "asset_hostname": "analyst-ws-03.shieldview.internal",
        "asset_ip": "10.0.10.33",
        "source_ip": "10.0.10.33",
        "raw_log": '{"timestamp":"2024-12-13T11:22:05Z","level":"ALERT","source":"auditd","host":"analyst-ws-03","user":"j.wilson","command":"sudo su -","result":"success","tty":"pts/2","pwd":"/home/j.wilson"}',
    },
    {
        "title": "Lateral movement detected from compromised endpoint",
        "description": "Host dev-api-02 initiated SMB connections to 12 internal hosts within 90 seconds using service account credentials. This pattern is consistent with automated lateral movement. The source host was flagged for malware 2 hours ago.",
        "severity": "HIGH",
        "asset_hostname": "dev-api-02.shieldview.internal",
        "asset_ip": "10.0.4.18",
        "source_ip": "10.0.4.18",
        "raw_log": '{"timestamp":"2024-12-14T16:08:33Z","level":"CRITICAL","source":"ndr","detection":"lateral-movement","src_host":"dev-api-02","protocol":"SMB","targets_count":12,"credential":"svc-deploy@SHIELDVIEW","time_window":"90s"}',
    },
    {
        "title": "New IAM admin role created in AWS",
        "description": "A new IAM role 'emergency-admin-temp' with AdministratorAccess policy was created by user 'deploy-bot'. This role was not part of any approved infrastructure change and has no expiration set.",
        "severity": "MEDIUM",
        "asset_hostname": "iam.amazonaws.com",
        "asset_ip": "99.86.0.15",
        "source_ip": "198.51.100.14",
        "raw_log": '{"timestamp":"2024-12-13T14:55:02Z","level":"WARNING","source":"cloudtrail","event":"CreateRole","role_name":"emergency-admin-temp","policy":"arn:aws:iam::aws:policy/AdministratorAccess","principal":"deploy-bot","mfa_used":false}',
    },
    {
        "title": "Docker exec into production container",
        "description": "User 'ops-engineer' executed 'docker exec -it' on container 'prod-api-v2' running on host prod-docker-01. Interactive shell access to production containers is restricted and requires approval.",
        "severity": "MEDIUM",
        "asset_hostname": "prod-docker-01.shieldview.internal",
        "asset_ip": "10.0.1.25",
        "source_ip": "10.0.10.33",
        "raw_log": '{"timestamp":"2024-12-14T13:40:18Z","level":"WARNING","source":"docker-audit","host":"prod-docker-01","container":"prod-api-v2","command":"docker exec -it prod-api-v2 /bin/bash","user":"ops-engineer"}',
    },
    {
        "title": "MFA bypass — session token reused",
        "description": "A session token for user 'm.rodriguez' was used from two different IP addresses within 30 seconds. The original session was from 10.0.10.40 and the duplicate appeared from 198.51.100.77. Possible session hijacking.",
        "severity": "MEDIUM",
        "asset_hostname": "auth.shieldview.io",
        "asset_ip": "34.120.50.10",
        "source_ip": "198.51.100.77",
        "raw_log": '{"timestamp":"2024-12-12T16:33:09Z","level":"WARNING","source":"auth-service","event":"session_anomaly","user":"m.rodriguez","original_ip":"10.0.10.40","duplicate_ip":"198.51.100.77","time_delta":"28s","token_id":"tok_3c9f..."}',
    },
    {
        "title": "Unauthorized software installation attempt",
        "description": "Endpoint agent blocked installation of 'nmap-7.94.exe' by user 'm.rodriguez' on analyst-ws-05. Network scanning tools are prohibited on analyst workstations per security policy AUP-2024-003.",
        "severity": "MEDIUM",
        "asset_hostname": "analyst-ws-05.shieldview.internal",
        "asset_ip": "10.0.10.35",
        "source_ip": "10.0.10.35",
        "raw_log": '{"timestamp":"2024-12-11T14:28:33Z","level":"WARNING","source":"endpoint-agent","host":"analyst-ws-05","event":"install_blocked","user":"m.rodriguez","software":"nmap-7.94.exe","policy":"AUP-2024-003","action":"blocked"}',
    },
    {
        "title": "User account locked after failed attempts",
        "description": "Account 'intern-temp01' was automatically locked after 5 consecutive failed login attempts. Last attempt was from IP 10.0.10.60. Account lockout duration is 30 minutes per policy.",
        "severity": "LOW",
        "asset_hostname": "auth.shieldview.io",
        "asset_ip": "34.120.50.10",
        "source_ip": "10.0.10.60",
        "raw_log": '{"timestamp":"2024-12-12T11:05:18Z","level":"INFO","source":"auth-service","event":"account_locked","user":"intern-temp01","failed_attempts":5,"src_ip":"10.0.10.60","lockout_duration":"1800s"}',
    },
    {
        "title": "Scheduled password rotation completed",
        "description": "Automated password rotation for 15 service accounts completed successfully. All accounts in the 'svc-*' prefix group had their passwords rotated and updated in the secrets vault.",
        "severity": "LOW",
        "asset_hostname": "vault.shieldview.internal",
        "asset_ip": "10.0.1.50",
        "source_ip": "10.0.1.50",
        "raw_log": '{"timestamp":"2024-12-13T02:00:00Z","level":"INFO","source":"password-manager","event":"rotation_complete","accounts_rotated":15,"prefix":"svc-*","vault_updated":true}',
    },
    {
        "title": "Antivirus signature database updated",
        "description": "Antivirus signature database on all managed endpoints updated to version 2024.12.14.001. Update includes 342 new malware signatures covering recent ransomware variants and info-stealers.",
        "severity": "LOW",
        "asset_hostname": "av-console.shieldview.internal",
        "asset_ip": "10.0.1.31",
        "source_ip": "10.0.1.31",
        "raw_log": '{"timestamp":"2024-12-14T07:00:00Z","level":"INFO","source":"antivirus","event":"signature_update","version":"2024.12.14.001","new_signatures":342,"endpoints_updated":45}',
    },
]

# Classified alerts — assigned to admin (user_id=1) — hidden, discoverable via IDOR
# Alert index ~21 contains the IDOR flag in its raw_log
CLASSIFIED_ALERTS = [
    {
        "title": "Ransomware encryption activity detected",
        "description": "Endpoint agent on prod-file-01 detected rapid file modification patterns consistent with ransomware encryption. Over 2,400 files were modified with new extensions (.locked) in under 3 minutes. Automated isolation triggered.",
        "severity": "HIGH",
        "asset_hostname": "prod-file-01.shieldview.internal",
        "asset_ip": "10.0.2.80",
        "source_ip": "10.0.2.80",
        "raw_log": '{"timestamp":"2024-12-09T22:14:55Z","level":"EMERGENCY","source":"endpoint-agent","host":"prod-file-01","detection":"ransomware","files_modified":2417,"new_extension":".locked","time_window":"180s","action":"host_isolated"}',
    },
    {
        "title": "[CLASSIFIED] Incident response — credential compromise",
        "description": "CLASSIFIED: Active incident response. Service account 'svc-deploy' credentials were found on a paste site. All systems using these credentials are being rotated. IR team lead: Sarah Chen.",
        "severity": "HIGH",
        "asset_hostname": "ir-case-mgmt.shieldview.internal",
        "asset_ip": "10.0.1.5",
        "source_ip": "185.220.101.33",
        "raw_log": '{"timestamp":"2024-12-15T02:30:00Z","level":"EMERGENCY","source":"incident-response","case_id":"IR-2024-0847","classification":"CLASSIFIED","lead":"s.chen@shieldview.io","ir_token":"' + FLAGS["idor_alerts"] + '","compromised_account":"svc-deploy","paste_url":"https://pastebin.com/REDACTED","status":"active"}',
    },
    {
        "title": "Data exfiltration to known C2 domain",
        "description": "Host analyst-ws-07 established HTTPS connection to known command-and-control domain 'update-service.malware-c2.xyz' and transferred approximately 340MB of data over a 15-minute period. DNS resolution was via external resolver.",
        "severity": "HIGH",
        "asset_hostname": "analyst-ws-07.shieldview.internal",
        "asset_ip": "10.0.10.47",
        "source_ip": "10.0.10.47",
        "raw_log": '{"timestamp":"2024-12-11T01:33:18Z","level":"CRITICAL","source":"proxy","host":"analyst-ws-07","dst_domain":"update-service.malware-c2.xyz","dst_ip":"185.220.101.33","bytes_sent":356515840,"duration":"900s","protocol":"HTTPS"}',
    },
    {
        "title": "SSH key added to root account on prod-k8s-master",
        "description": "A new SSH public key was added to /root/.ssh/authorized_keys on the Kubernetes master node. The key was added via an interactive session from IP 10.0.4.18 (dev-api-02), which is currently under investigation for compromise.",
        "severity": "HIGH",
        "asset_hostname": "prod-k8s-master.shieldview.internal",
        "asset_ip": "10.0.1.10",
        "source_ip": "10.0.4.18",
        "raw_log": '{"timestamp":"2024-12-14T17:01:44Z","level":"CRITICAL","source":"fim","host":"prod-k8s-master","file":"/root/.ssh/authorized_keys","action":"modified","user":"root","remote_ip":"10.0.4.18","key_fingerprint":"SHA256:xK9d2..."}',
    },
    {
        "title": "Login from previously unseen country",
        "description": "User 's.chen' logged in to the admin portal from an IP geolocated to Romania (RO). All previous logins for this user originated from Israel (IL) and the United States (US). Session is currently active.",
        "severity": "MEDIUM",
        "asset_hostname": "admin-portal.shieldview.io",
        "asset_ip": "34.120.50.10",
        "source_ip": "86.124.77.33",
        "raw_log": '{"timestamp":"2024-12-11T19:05:44Z","level":"WARNING","source":"auth-service","event":"login_anomaly","user":"s.chen","src_ip":"86.124.77.33","geo":"RO","previous_geos":["IL","US"],"session_id":"sess_8f2a..."}',
    },
    {
        "title": "Unusual database query volume",
        "description": "Application service account 'app-readonly' executed 14,500 SELECT queries against the users table in a 10-minute window, which is 12x the normal baseline. Query patterns suggest data enumeration.",
        "severity": "MEDIUM",
        "asset_hostname": "prod-db-01.shieldview.internal",
        "asset_ip": "10.0.2.50",
        "source_ip": "10.0.3.15",
        "raw_log": '{"timestamp":"2024-12-13T20:12:55Z","level":"WARNING","source":"db-monitor","host":"prod-db-01","user":"app-readonly","table":"users","query_count":14500,"window":"600s","baseline_avg":1200}',
    },
    {
        "title": "DNS tunneling pattern detected",
        "description": "DNS monitoring detected high-entropy subdomain queries from host 10.0.10.47 to domain 'x4f2a.data-tunnel.net'. Query frequency and subdomain length are consistent with DNS-based data exfiltration tunneling.",
        "severity": "MEDIUM",
        "asset_hostname": "analyst-ws-07.shieldview.internal",
        "asset_ip": "10.0.10.47",
        "source_ip": "10.0.10.47",
        "raw_log": '{"timestamp":"2024-12-09T23:44:01Z","level":"WARNING","source":"dns-monitor","detection":"dns-tunneling","src_ip":"10.0.10.47","domain":"x4f2a.data-tunnel.net","query_rate":"85/min","avg_subdomain_len":42,"entropy":0.94}',
    },
    {
        "title": "Firewall rule modified — outbound traffic allowed",
        "description": "Firewall rule 'FW-DENY-OUTBOUND-ALL' on segment prod-db was modified to allow outbound traffic on ports 443 and 8443. Change was made by 'fw-admin' with no corresponding change ticket in ServiceNow.",
        "severity": "MEDIUM",
        "asset_hostname": "fw-core-01.shieldview.internal",
        "asset_ip": "10.0.0.1",
        "source_ip": "10.0.10.15",
        "raw_log": '{"timestamp":"2024-12-13T09:15:40Z","level":"WARNING","source":"firewall","event":"rule_modified","rule":"FW-DENY-OUTBOUND-ALL","change":"allow_ports_443_8443","segment":"prod-db","user":"fw-admin","ticket":"none"}',
    },
    {
        "title": "Backup job completed successfully",
        "description": "Daily backup of production database prod-db-01 completed successfully. Backup size: 4.2GB compressed. Verified checksum matches. Stored to s3://shieldview-backups/daily/2024-12-14/.",
        "severity": "LOW",
        "asset_hostname": "prod-db-01.shieldview.internal",
        "asset_ip": "10.0.2.50",
        "source_ip": "10.0.1.100",
        "raw_log": '{"timestamp":"2024-12-14T04:30:00Z","level":"INFO","source":"backup-agent","host":"prod-db-01","status":"success","size_gb":4.2,"checksum":"sha256:a8b3f2...","destination":"s3://shieldview-backups/daily/2024-12-14/"}',
    },
    {
        "title": "GitHub repository made public",
        "description": "Repository 'shieldview/internal-scripts' visibility was changed from private to public by user 'dev-lead'. Repository contains infrastructure automation scripts. Reviewing for exposed secrets.",
        "severity": "LOW",
        "asset_hostname": "github.com",
        "asset_ip": "140.82.121.3",
        "source_ip": "10.0.10.33",
        "raw_log": '{"timestamp":"2024-12-14T10:22:15Z","level":"INFO","source":"github-audit","event":"repo_visibility_change","repo":"shieldview/internal-scripts","from":"private","to":"public","actor":"dev-lead"}',
    },
]


def seed_log_files():
    """Create sample log files and a hidden flag.txt for the path traversal vuln."""
    os.makedirs(LOGS_DIR, exist_ok=True)

    log_files = {
        "alert_001.log": '2024-12-10 14:32:01 [CRITICAL] endpoint-agent prod-web-03: Process mimikatz.exe executed by svc-backup (PID 8841)\n2024-12-10 14:32:02 [INFO] endpoint-agent: Hash verification: a4b35de71b20...\n2024-12-10 14:32:03 [ACTION] endpoint-agent: Process terminated, host flagged for review\n',
        "alert_002.log": '2024-12-11 03:15:22 [ALERT] ids: SSH brute force detected\n2024-12-11 03:15:22 [INFO] ids: Source 203.0.113.89 -> 10.0.2.50:22, 847 attempts in 300s\n2024-12-11 03:15:23 [ACTION] firewall: Source IP blocked for 24h\n',
        "alert_003.log": '2024-12-12 09:45:11 [CRITICAL] cloudtrail: S3 bucket ACL change detected\n2024-12-12 09:45:11 [INFO] cloudtrail: Bucket shieldview-prod-backups set to public-read by deploy-bot\n2024-12-12 09:45:12 [ACTION] s3-guard: ACL reverted, alert escalated to IR team\n',
        "system.log": '2024-12-14 00:00:00 [INFO] shieldview-soc: Daily rotation started\n2024-12-14 00:00:01 [INFO] db: WAL checkpoint completed\n2024-12-14 00:00:02 [INFO] auth: Session cleanup - 12 expired sessions removed\n2024-12-14 00:00:03 [INFO] webhook: Flush queue - 0 pending events\n',
    }
    for filename, content in log_files.items():
        filepath = os.path.join(LOGS_DIR, filename)
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                f.write(content)

    # Hidden flag file for path traversal discovery
    flag_path = os.path.join(DATA_DIR, "flag.txt")
    if not os.path.exists(flag_path):
        with open(flag_path, "w") as f:
            f.write(f"Congratulations! You found the path traversal vulnerability.\n\n{FLAGS['path_traversal']}\n")


def seed_database():
    init_db()
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row

    existing = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE is_seed = 1").fetchone()
    if existing and existing[0] > 0:
        conn.close()
        print("Database already seeded. Use reset.sh to re-seed.")
        seed_log_files()
        return

    for user in SEED_USERS:
        conn.execute(
            "INSERT INTO users (email, password, display_name, role, is_seed, last_login) VALUES (?, ?, ?, ?, ?, ?)",
            (user["email"], user["password"], user["display_name"], user["role"], user["is_seed"],
             (datetime.utcnow() - timedelta(hours=random.randint(1, 48))).isoformat()),
        )
    conn.commit()

    # Seed the secret_flags table (discoverable via SQLi UNION injection)
    conn.execute(
        "INSERT INTO secret_flags (flag_name, flag_value, hint) VALUES (?, ?, ?)",
        ("sqli_master", FLAGS["sqli"], "You found this via SQL injection. Well done."),
    )
    conn.commit()

    user_ids = {row["email"]: row["id"] for row in conn.execute("SELECT id, email FROM users WHERE is_seed = 1")}

    now = datetime.utcnow()

    # Seed Team Alpha alerts → analyst1 (visible on dashboard)
    for alert in TEAM_ALPHA_ALERTS:
        hours_ago = random.randint(1, 168)
        created_at = (now - timedelta(hours=hours_ago)).isoformat()
        conn.execute(
            """INSERT INTO alerts (title, description, severity, asset_hostname, asset_ip, source_ip, raw_log, assigned_to, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["title"], alert["description"], alert["severity"],
             alert["asset_hostname"], alert["asset_ip"], alert["source_ip"],
             alert["raw_log"], user_ids["analyst1@shieldview.io"], created_at),
        )

    # Seed Team Beta alerts → analyst2 (hidden from dashboard)
    for alert in TEAM_BETA_ALERTS:
        hours_ago = random.randint(1, 168)
        created_at = (now - timedelta(hours=hours_ago)).isoformat()
        conn.execute(
            """INSERT INTO alerts (title, description, severity, asset_hostname, asset_ip, source_ip, raw_log, assigned_to, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["title"], alert["description"], alert["severity"],
             alert["asset_hostname"], alert["asset_ip"], alert["source_ip"],
             alert["raw_log"], user_ids["analyst2@shieldview.io"], created_at),
        )

    # Seed Classified alerts → admin (hidden, discoverable via IDOR — includes IDOR flag)
    for alert in CLASSIFIED_ALERTS:
        hours_ago = random.randint(1, 168)
        created_at = (now - timedelta(hours=hours_ago)).isoformat()
        conn.execute(
            """INSERT INTO alerts (title, description, severity, asset_hostname, asset_ip, source_ip, raw_log, assigned_to, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert["title"], alert["description"], alert["severity"],
             alert["asset_hostname"], alert["asset_ip"], alert["source_ip"],
             alert["raw_log"], user_ids["admin@shieldview.io"], created_at),
        )

    # ── Seed Incident Reports ──────────────────────────────────────
    SEED_REPORTS = [
        {
            "title": "Brute-force attack on VPN gateway",
            "content": "Multiple failed login attempts detected from 203.0.113.42 targeting the corporate VPN gateway. Over 1,200 attempts in 15 minutes using a credential stuffing wordlist. Geo-IP shows origin as Eastern Europe. Recommended action: block source IP at perimeter firewall and enforce MFA.",
            "alert_id": 1,
            "created_by": user_ids["analyst1@shieldview.io"],
            "author_name": "James Wilson",
            "status": "investigating",
        },
        {
            "title": "Suspicious PowerShell execution on WKSTN-042",
            "content": "Encoded PowerShell command detected on workstation WKSTN-042. The command decodes to a reverse shell connecting to 198.51.100.77:4444. User account compromised: jsmith@corp.local. Host has been isolated from the network pending forensic analysis.",
            "alert_id": 3,
            "created_by": user_ids["analyst1@shieldview.io"],
            "author_name": "James Wilson",
            "status": "open",
        },
        {
            "title": "Data exfiltration via DNS tunneling",
            "content": "Anomalous DNS query pattern detected from DB-PROD-01. Queries contain base64-encoded payloads in subdomain labels, consistent with dns2tcp or iodine tunneling. Approximately 45MB of data transferred over 6 hours. The internal security token for this report is: <!-- " + FLAGS["stored_xss"] + " --> Investigation ongoing.",
            "alert_id": 5,
            "created_by": user_ids["admin@shieldview.io"],
            "author_name": "Sarah Chen",
            "status": "escalated",
        },
        {
            "title": "Unauthorized S3 bucket access",
            "content": "AWS CloudTrail logs show unauthorized GetObject calls on s3://shieldview-backups from an unknown IAM role arn:aws:iam::123456789012:role/temp-role-debug. 230 objects accessed including database snapshots. Access key has been revoked. Full audit in progress.",
            "alert_id": 7,
            "created_by": user_ids["analyst2@shieldview.io"],
            "author_name": "Maya Rodriguez",
            "status": "resolved",
        },
        {
            "title": "Lateral movement detected — Pass-the-Hash",
            "content": "NTLM authentication logs show pass-the-hash activity from WKSTN-042 to DC-01 using the compromised jsmith account. Attacker leveraged local admin privileges to extract NTLM hashes via Mimikatz. Domain admin credentials may be compromised. Emergency password reset initiated for all privileged accounts.",
            "alert_id": 9,
            "created_by": user_ids["analyst1@shieldview.io"],
            "author_name": "James Wilson",
            "status": "escalated",
        },
    ]

    for report in SEED_REPORTS:
        hours_ago = random.randint(1, 72)
        created_at = (now - timedelta(hours=hours_ago)).isoformat()
        conn.execute(
            """INSERT INTO incident_reports (title, content, alert_id, created_by, author_name, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (report["title"], report["content"], report["alert_id"],
             report["created_by"], report["author_name"], report["status"], created_at),
        )

    conn.commit()
    conn.close()

    total_alerts = len(TEAM_ALPHA_ALERTS) + len(TEAM_BETA_ALERTS) + len(CLASSIFIED_ALERTS)
    print(f"Seeded {len(SEED_USERS)} users, {total_alerts} alerts, {len(SEED_REPORTS)} incident reports, and 1 secret flag.")

    seed_log_files()


if __name__ == "__main__":
    seed_database()
