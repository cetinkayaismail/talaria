# Enterprise Telemetry & SIEM Integration Guide

**Document ID:** INT-TALARIA-2026-V2  
**Classification:** Tier-1 Enterprise / Institutional Banking Security Standard  
**Compliance Baseline:** PCI-DSS v4.0 Req 10.2 / 10.3, SOC 2 Type II CC7.2, NIST SP 800-53 AU-6  
**Target Systems:** Splunk Cloud / Enterprise, Elastic SIEM, Datadog Security, Vector, FluentBit, ServiceNow  

---

## 1. Formal JSON Schema Specification (Draft 2020-12)

Talaria generates structured telemetry compliant with **JSON Schema Draft 2020-12**. This guarantees backward-compatible contract enforcement across enterprise data ingestion pipelines.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://talaria.bank.corp/schemas/v2/audit-report.json",
  "title": "TalariaAuditReport",
  "type": "object",
  "required": ["scan_time", "target_user", "target_scan_path", "audit_mode"],
  "properties": {
    "scan_time": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of audit execution initiation"
    },
    "target_user": {
      "type": "string",
      "description": "Operating system username executing the assessment"
    },
    "target_scan_path": {
      "type": "string",
      "description": "Root filesystem traversal target path"
    },
    "audit_mode": {
      "type": "boolean",
      "description": "Whether credential masking and enterprise compliance flags were active"
    },
    "suid": {
      "type": "array",
      "items": { "$ref": "#/$defs/FindingItem" }
    },
    "capabilities": {
      "type": "array",
      "items": { "$ref": "#/$defs/FindingItem" }
    },
    "sudo_privileges": {
      "type": "array",
      "items": { "$ref": "#/$defs/FindingItem" }
    },
    "cron_jobs": {
      "type": "array",
      "items": { "$ref": "#/$defs/FindingItem" }
    },
    "secrets": {
      "type": "array",
      "items": { "$ref": "#/$defs/FindingItem" }
    },
    "writeable": {
      "type": "array",
      "items": { "$ref": "#/$defs/FindingItem" }
    },
    "attack_chains": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["chain_name", "risk_level", "description", "steps"],
        "properties": {
          "chain_name": { "type": "string" },
          "risk_level": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "INFO"] },
          "description": { "type": "string" },
          "steps": { "type": "array", "items": { "type": "string" } }
        }
      }
    }
  },
  "$defs": {
    "FindingItem": {
      "type": "object",
      "required": ["path", "is_dangerous", "reason"],
      "properties": {
        "path": { "type": "string" },
        "is_dangerous": { "type": "boolean" },
        "reason": { "type": "string" },
        "risk_level": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "INFO"] },
        "exploit_hint": { "type": "string" },
        "remediation": { "type": "string" },
        "compliance_tag": { "type": "string" }
      }
    }
  }
}
```

---

## 2. Splunk Enterprise & Splunk Cloud Blueprint

### 2.1 `inputs.conf` (Splunk Universal Forwarder)
Place in `/opt/splunkforwarder/etc/apps/talaria_inputs/local/inputs.conf`:
```ini
[monitor:///var/log/talaria/*.json]
disabled = 0
index = security_audit
sourcetype = talaria:json
crcSalt = <SOURCE>
```

### 2.2 `props.conf` (Search Head / Indexer)
Place in `/opt/splunk/etc/apps/talaria_props/local/props.conf`:
```ini
[talaria:json]
SHOULD_LINEMERGE = false
INDEXED_EXTRACTIONS = json
KV_MODE = none
AUTO_KV_COMPLETION = false
TIMESTAMP_FIELDS = scan_time
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z
TRUNCATE = 0
FIELDALIAS-talaria_host = host AS dvc
EVAL-vendor_product = "Talaria Institutional Scanner"
```

### 2.3 Splunk High-Severity Alert Search (SPL)
```spl
index=security_audit sourcetype="talaria:json"
| spath path=suid{} output=suid_finding
| mvexpand suid_finding
| spath input=suid_finding
| search is_dangerous=true
| table _time, host, target_user, path, reason, remediation, compliance_tag
| where isnotnull(path)
```

---

## 3. Elastic SIEM / ELK Stack Blueprint

### 3.1 Logstash Pipeline Configuration (`/etc/logstash/conf.d/talaria.conf`)
```ruby
input {
  file {
    path => "/var/log/talaria/*.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_talaria"
    codec => "json"
    tags => ["talaria", "host_audit"]
  }
}

filter {
  date {
    match => [ "scan_time", "ISO8601" ]
    target => "@timestamp"
  }
  
  mutate {
    add_field => {
      "[event][module]" => "talaria"
      "[event][category]" => "vulnerability"
      "[event][kind]" => "alert"
      "[ecs][version]" => "8.11.0"
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch.bank.corp:9200"]
    index => "talaria-audit-%{+YYYY.MM}"
    ssl => true
    cacert => "/etc/logstash/certs/ca.crt"
    api_key => "${ELASTIC_INGEST_API_KEY}"
  }
}
```

### 3.2 Elasticsearch Index Mappings
```json
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "scan_time": { "type": "date" },
      "target_user": { "type": "keyword" },
      "target_scan_path": { "type": "keyword" },
      "audit_mode": { "type": "boolean" },
      "suid": {
        "properties": {
          "path": { "type": "keyword" },
          "is_dangerous": { "type": "boolean" },
          "reason": { "type": "text" },
          "compliance_tag": { "type": "keyword" },
          "remediation": { "type": "text" }
        }
      }
    }
  }
}
```

---

## 4. Datadog Agent Configuration

Add configuration file `/etc/datadog-agent/conf.d/talaria.d/conf.yaml`:
```yaml
logs:
  - type: file
    path: /var/log/talaria/audit.json
    service: talaria-lpe-audit
    source: talaria
    sourcecategory: security
    tags:
      - env:production
      - compliance:pci-dss
    log_processing_rules:
      - type: multi_line
        name: new_log_start
        pattern: '\{\s*"scan_time"'
```

---

## 5. Vector Streaming Pipeline (to Grafana Loki & Kafka)

`/etc/vector/vector.yaml`:
```yaml
sources:
  talaria_logs:
    type: file
    include:
      - /var/log/talaria/*.json
    read_from: beginning

transforms:
  parse_talaria:
    type: remap
    inputs:
      - talaria_logs
    source: |
      . = parse_json!(.message)
      .@timestamp = .scan_time
      .service = "talaria"

sinks:
  kafka_siem:
    type: kafka
    inputs:
      - parse_talaria
    bootstrap_servers: "kafka-cluster.bank.corp:9092"
    topic: "security.audit.host-privesc"
    encoding:
      codec: json
    tls:
      enabled: true
      ca_file: "/etc/ssl/certs/internal-ca.crt"

  loki_storage:
    type: loki
    inputs:
      - parse_talaria
    endpoint: "https://loki.bank.corp:3100"
    encoding:
      codec: json
    labels:
      app: "talaria"
      user: "{{ target_user }}"
```

---

## 6. Incident Alert Routing Payloads

### 6.1 PagerDuty Events API v2 (Critical Findings & Attack Chains)
```json
{
  "routing_key": "${PAGERDUTY_INTEGRATION_KEY}",
  "event_action": "trigger",
  "dedup_key": "talaria-critical-${HOSTNAME}-suid",
  "payload": {
    "summary": "CRITICAL LPE Vector Identified by Talaria on Host ${HOSTNAME}",
    "source": "${HOSTNAME}",
    "severity": "critical",
    "timestamp": "2026-09-02T20:30:00Z",
    "component": "Host OS Security Baseline",
    "group": "Infrastructure Security",
    "class": "Privilege Escalation Misconfiguration",
    "custom_details": {
      "target_user": "appuser",
      "finding_type": "SUID Binary / GTFOBins Shell Escape",
      "binary_path": "/usr/local/bin/custom_wrapper",
      "compliance_violation": "CIS-6.1.13 / NIST-AC-6(1)",
      "remediation": "chmod u-s /usr/local/bin/custom_wrapper"
    }
  }
}
```

### 6.2 ServiceNow ITSM Security Incident Response (SIR)
```json
{
  "short_description": "Talaria LPE Compliance Finding: /etc/sudoers NOPASSWD ALL",
  "description": "Talaria host audit identified unauthenticated root escalation privilege on production cluster node.",
  "caller_id": "secops.automation@bank.corp",
  "urgency": "1",
  "impact": "1",
  "priority": "1",
  "category": "Security",
  "subcategory": "Host Hardening Violation",
  "cmdb_ci": "${HOSTNAME}",
  "work_notes": "Authoritative Fix: Remove NOPASSWD directive from /etc/sudoers.d/appuser"
}
```
