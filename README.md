# Splunk Incident Handling — Security Detection Lab

---

## 1. Project Overview

This project demonstrates the end-to-end process of ingesting, parsing, and detecting security incidents using **Splunk Enterprise** and **Splunk Security Essentials (SSE)**. Using three simulated log files representing a real-world attack chain against a fictional organisation (Apex Financial), the project covers the full pipeline from raw log ingestion through to scheduled detection alerts and showing the potential of SSE.

The attack scenario spans a complete kill chain: a spear-phishing email delivering a malicious macro, credential attacks including pass-the-hash, lateral movement via WMI and PsExec, persistence via scheduled task and registry modification, and culminating in ransomware execution (ShadowCrypt).

**Main objective:** Build a functioning detection pipeline in Splunk that identifies each stage of a multi-phase cyberattack using structured log data, scheduled alerts.

---

## 2. Project Relevance

### Why Splunk in Incident Response?

Splunk is one of the most widely deployed SIEM (Security Information and Event Management) platforms in enterprise security operations. During an incident, Splunk serves as the central log aggregation and analysis engine, which allows analysts to:

- **Correlate events** across multiple data sources (authentication, endpoint, email, network) in a single search
- **Detect attack patterns** through scheduled searches and correlation rules that fire when suspicious conditions are met
- **Investigate timelines** by pivoting on indicators such as source IPs, user accounts, and hostnames
- **Triage alerts** through dashboards and triggered alert queues that surface the most critical events first

Splunk is used at **every phase of the IR lifecycle**:

| IR Phase | Splunk Usage |
|---|---|
| Preparation | Onboarding data sources, building detection rules |
| Detection | Scheduled alerts and correlation searches fire on anomalies |
| Analysis | SPL queries pivot across indexes to reconstruct attack timeline. Mapping to MITRE. |
| Containment | Identifying scope (which hosts, users, IPs are affected) |
| Eradication | Confirming malicious artifacts are no longer present in logs |
| Recovery | Monitoring for re-infection or persistence mechanisms |
| Lessons Learned | Refining detection rules based on what was missed |

### Skills Gained

Working through this project develops practical skills in:
- Splunk architecture — indexes, sourcetypes, forwarders, props.conf
- SPL (Search Processing Language) — stats, eval, join, where, table
- CIM (Common Information Model) — normalising data for cross-source correlation (used by SSE)
- Detection engineering — writing rules based on behavioural indicators rather than signatures
- MITRE ATT&CK mapping — linking detections to real-world adversary techniques
- Splunk Security Essentials — navigating a production security content library

---

## 3. Methodology

### Environment

| Component | Detail |
|---|---|
| Platform | Splunk Enterprise (60-day free trial) |
| Version | Latest as of April 2026 |
| Deployment | Single instance, local installation |
| Add-ons | Splunk Security Essentials (SSE), Splunk CIM Add-on |
| OS | Windows / Linux (single node) |

### Dataset

Three simulated log files representing a fictional incident at Apex Financial on 2025-03-06:

| File | Log Type | Index | Sourcetype | Events |
|---|---|---|---|---|
| `authentication.txt` | Auth events (logins, attacks) | `auth_logs` | `school:auth` | 26 |
| `email_gateway.txt` | Email delivery logs | `email_logs` | `school:email` | 14 |
| `endpoint_security.txt` | Endpoint process/malware events | `endpoint_logs` | `school:endpoint` | 28 |

All logs are JSON-formatted with fields: `timestamp`, `log_type`, `source_ip`, `destination_ip`, `event_description`, `severity`.

### Architecture / Data Pipeline

```
Raw JSON Log Files
        │
        ▼
Splunk Add Data (Upload)
  ├── sourcetype assigned (school:auth / school:email / school:endpoint)
  ├── KV_MODE = json (field extraction)
  ├── SHOULD_LINEMERGE = false
  └── Timestamp extracted from JSON timestamp field
        │
        ▼
Splunk Indexes
  ├── auth_logs
  ├── email_logs
  └── endpoint_logs
        │
        ▼
CIM Data Model Mapping
  ├── Authentication data model → index=auth_logs sourcetype=school:auth
  ├── Email data model         → index=email_logs sourcetype=school:email
  └── Endpoint data model      → index=endpoint_logs sourcetype=school:endpoint
        │
        ▼
Custom Detection Rules (SPL Saved Searches → Scheduled Alerts)
  ├── Credential Attack Detection
  ├── High Severity Endpoint Activity
  ├── Phishing-to-Auth Escalation (cross-index join)
  └── Lateral Movement (dc of destination IPs)
        │
        ▼
Triggered Alerts → index=main (sourcetype=school:alerts)
        │
        ▼
Splunk Security Essentials
  └── Data Inventory → CIM Mapping → MITRE ATT&CK Content Library
```

### Step-by-Step Process

#### Step 1 — Data Ingestion
Each log file was uploaded via **Settings → Add Data → Upload**. During the Set Source Type stage the following advanced settings were configured manually:

```ini
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
```

Each file was assigned a distinct sourcetype and routed to its own index. Timestamps were extracted from the `timestamp` field in the JSON payload using Auto detection, preserving the original March 2025 event chronology.

**Set Source Type — advanced settings configured for JSON parsing:**

![Set Source Type](images/ingest_auth_set_source.jpg)

**Input Settings — host field value and index assignment:**

![Input Settings](images/index_Auth.jpg)

#### Step 2 — Verify Ingestion
```spl
index=auth_logs OR index=email_logs OR index=endpoint_logs
| stats count by index, sourcetype
```
Confirmed 68 total events across all three indexes.

![Total events across all three indexes](images/total_events.jpg)

#### Step 3 — Build Detection Rules

Five custom detection searches were written using severity-based logic rather than pattern matching on event descriptions, making them more realistic and vendor-agnostic:

**Detection 1 — Credential Attack**
```spl
index=auth_logs
severity IN ("HIGH", "WARNING")
| stats count by source_ip, destination_ip
| where count >= 2
| eval detection="Potential Credential Attack"
| table source_ip, destination_ip, count, detection
```

![Credential Attack detection search result — 192.168.1.10 flagged with count of 3](images/query_for_alert.png)

**Detection 2 — High Severity Endpoint Activity**
```spl
index=endpoint_logs
severity IN ("CRITICAL", "HIGH")
| stats count by source_ip, severity
| eval detection=case(
    severity="CRITICAL", "Critical Endpoint Threat",
    severity="HIGH", "High Severity Endpoint Event"
)
| table source_ip, severity, detection
```

**Detection 3 — Phishing-to-Auth Escalation (cross-index)**
```spl
index=email_logs
| stats count as email_count by destination_ip
| rename destination_ip as source_ip
| join source_ip
    [search index=auth_logs severity IN ("HIGH","WARNING")
    | stats count as auth_count by source_ip]
| where email_count > 0 AND auth_count > 0
| eval detection="Phishing-to-Auth Escalation"
| table source_ip, email_count, auth_count, detection
```

**Detection 4 — Lateral Movement**
```spl
index=endpoint_logs
severity IN ("HIGH", "CRITICAL")
| where destination_ip != "N/A"
| stats count as tool_count, values(event_description) as activity, values(destination_ip) as destination by source_ip
| eval detection="Potential Lateral Movement"
| table source_ip, destination, tool_count, activity, detection
```


#### Step 4 — Save as Scheduled Alerts

Each detection was saved as a scheduled alert with:
- **Schedule:** `*/5 * * * *` (every 5 minutes)
- **Time Range:** All time (to cover static March 2025 log timestamps)
- **Trigger:** Number of results greater than 0
- **Action:** Log Event to `index=main`, `sourcetype=school:alerts`

Log Event token template:
```
DETECTION FIRED: $result.detection$ - Source IP: $result.source_ip$ - Destination IP: $result.destination_ip$ - Event Count: $result.count$
```

**Saving a search as an alert via Save As → Alert:**

![Save As Alert menu](images/save_query_to_alert.png)

**Alert settings — scheduled, cron expression, time range, trigger conditions:**

![Alert settings configuration](images/First_Save_Alert.png)

**Log Event action — token variables, sourcetype, host, index:**

![Log Event trigger action configuration](images/Second_Save_Alert.png)

#### Step 5 — CIM Mapping for SSE
The three data models were configured in **Settings → Data Models** with direct constraints:

| Data Model | Constraint |
|---|---|
| Authentication | `index=auth_logs sourcetype=school:auth` |
| Email | `index=email_logs sourcetype=school:email` |
| Endpoint | `index=endpoint_logs sourcetype=school:endpoint` |

#### Step 6 — Splunk Security Essentials
Splunk Security Essentials is a free app available on Splunkbase that extends Splunk Enterprise with a library of over 1,000 pre-built security detections mapped directly to the MITRE ATT&CK framework. It provides guided data onboarding, a content browser organised by tactic and technique, and a security posture dashboard that visually shows which ATT&CK techniques you have detection coverage for across your data sources. SSE is designed to sit on top of an existing Splunk deployment and help security teams move from raw data to actionable detections without needing to write every SPL search from scratch.

SSE was installed from a `.tar.gz` package via **Apps → Manage Apps → Install app from file**. After restart, the Splunk CIM Add-on was installed and custom products were manually added in **Data → Data Inventory** for each of the three data sources.

However, the free trial combined with this log setup makes it difficult to get a realistic example of SSE working end to end. The majority of SSE's most relevant detections require either Splunk Enterprise Security (the paid premium product) or data that conforms strictly to Splunk's Common Information Model via properly tagged sourcetypes and accelerated data models. Custom JSON logs uploaded manually, as used in this lab, lack the CIM-normalised fields that SSE detections expect, meaning most searches either return no results or fall back to demo data rather than firing against the actual indexed events.

---

## 4. Results

### Attack Timeline Reconstructed

| Time (UTC) | Index | Event | Severity | MITRE Technique |
|---|---|---|---|---|
| 16:59 | email_logs | Spear-phishing email delivered to user@apexfinancial.com | INFO | T1566 - Phishing |
| 17:04 | endpoint_logs | Malicious macro executed from Q1_Performance_Review.pdf | HIGH | T1059 - Execution |
| 17:29 | auth_logs | Failed login attempt for user 'analyst1' | WARNING | T1110 - Brute Force |
| 17:34 | auth_logs | Successful login for user 'analyst1' | INFO | T1078 - Valid Accounts |
| 18:04 | auth_logs | Pass-the-hash attempt detected | HIGH | T1550.002 - Pass the Hash |
| 18:14 | endpoint_logs | WMI remote execution detected | HIGH | T1047 - WMI |
| 18:19 | endpoint_logs | PsExec execution detected | HIGH | T1569 - PsExec |
| 18:29 | auth_logs | Kerberos ticket request from unusual host | WARNING | T1558 - Kerberos Abuse |
| 18:29 | endpoint_logs | Scheduled task 'SystemUpdate' modified | MEDIUM | T1053 - Scheduled Task |
| 18:34 | endpoint_logs | New process spawned by svchost.exe | MEDIUM | T1543 - System Services |
| 19:44 | auth_logs | Account lockout attempt for 'domain_admin' | WARNING | T1110 - Brute Force |
| 19:59 | endpoint_logs | Ransomware executed: ShadowCrypt | CRITICAL | T1486 - Data Encrypted for Impact |
| 20:04 | endpoint_logs | Registry key modified for persistence | MEDIUM | T1547 - Registry Run Keys |

### Alerts Fired

All five scheduled alerts fired successfully, visible in `index=main sourcetype=school:alerts`:

- **DETECT - Credential Attack** — fired every 5 minutes, identifying `192.168.1.10` as the primary threat actor IP
- **DETECT - Endpoint Security Alert** — fired on 4 HIGH/CRITICAL endpoint events from `192.168.1.10` and `192.168.1.200`
- **DETECT - Phishing-to-Auth Escalation** — cross-index join confirmed `192.168.1.10` received phishing email then generated HIGH auth events
- **DETECT - Lateral Movement** — `192.168.1.10` authenticated to 3+ unique destination hosts
- **DETECT - Kill Chain Progression** — `192.168.1.10` triggered 4 of 5 severity escalation stages

**Alert events visible in index=main showing all three detection types firing:**

![Fired alerts in Splunk showing detection events](images/Fired_alerts.jpg)


### Key Finding

The primary threat actor IP `192.168.1.10` appeared across all three log sources, establishing a clear chain from phishing delivery → credential compromise → lateral movement → ransomware. The cross-index detection (Detection 3) was the most significant — it correlated email and authentication data to identify the pivot point between initial access and credential attack without any endpoint data, demonstrating the value of multi-source correlation.

---

## 5. Conclusion

### Key Insights

**Detection engineering without signatures is possible and more robust.** The most important lesson from this project was rewriting detection rules to avoid pattern matching on `event_description` — a field that wouldn't exist in real raw logs. By building detections on `severity`, `source_ip`, `dc(destination_ip)`, and cross-index joins, the rules became vendor-agnostic and would function on any normalised log source.

**CIM normalisation is the prerequisite for everything.** SSE, data models, and any Splunk security app all depend on data being mapped to CIM. Getting data into an index is only half the job, normalising it to a common schema is what makes it actionable across tools.

**Static log files require special handling.** Because the incident logs had fixed timestamps from March 2025, scheduled alerts needed to be set to "All time" rather than a rolling window. In a live environment with a Universal Forwarder streaming events in real time, this wouldn't be an issue, but it's an important consideration when building detection labs from historical data.

**The kill chain is visible in the data when you know where to look.** Without any threat intelligence or prior knowledge, the multi-stage attack progression from phishing to ransomware was fully reconstructable from three log files using basic SPL. The attacker's primary IP (`192.168.1.10`) appeared in every stage, and the time-ordered sequence of severity escalations told the complete story.

### Lessons Learned

- Sourcetype configuration matters enormously — incorrect `SHOULD_LINEMERGE` or `KV_MODE` settings silently break field extraction and produce empty search results
- Splunk Security Essentials requires the CIM Add-on and data model mapping before it can surface relevant detections — it does not read raw indexes directly
- Most SSE detections require Splunk Enterprise Security (paid) — on the free trial, custom SPL-based alerts provide equivalent detection capability for lab purposes
- Token variables in alert actions (`$result.fieldname$`) only resolve fields that exist in the final `| table` command of the search

### Potential Improvements

- **Add a Universal Forwarder** to stream live log data rather than static uploads, making scheduled alerts function with rolling time windows
- **Implement Sysmon** as the endpoint log source to replace the simulated `event_description` field with real Windows telemetry (EventIDs, process trees, command lines)
- **Build a detection dashboard** consolidating all five alert feeds into a single incident timeline view
- **Expand to network logs** adding firewall or DNS data would enable detection of C2 communication and data exfiltration stages not covered by the current three sources
- **Upgrade to Splunk Enterprise Security** to access the full correlation search framework, risk-based alerting, and Notable Events workflow used in production SOC environments

---