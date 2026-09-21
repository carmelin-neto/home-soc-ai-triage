# Home SOC with AI-Assisted Alert Triage

**Type:** A self-hosted SOC stack (Wazuh SIEM ingesting real Suricata detection data from [ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing)) with a locally-run LLM triage layer on top — built, broken, debugged, and validated end to end, including an honest scoring of where the AI got it right and where it didn't.

**Why this project exists:** Several roles I've applied to explicitly ask for comfort with AI-assisted security tooling — using an LLM to help triage alerts, not replace analyst judgment. This project builds that pipeline for real, with a real detected attack, and then does the part most AI-in-security demos skip: checks the AI's output against ground truth instead of just showing it produced *an* answer.

---

## Part 1: Building the SIEM Layer

**Stack:** Wazuh 4.9.0 (SIEM/XDR), deployed via Docker, ingesting the real Suricata `eve.json` alert data from the Modbus attack tested in Project 3.

### The setup wasn't clean — and that's worth documenting honestly

**Problem 1: Incomplete quickstart.** Wazuh's documented quickstart (`curl`-ing just the `docker-compose.yml` and cert-generator files) fails — it's missing the `config/` directory the compose file depends on, causing a "not a directory" mount error on first startup. Fixed by cloning the full repository (`git clone ... -b v4.9.0`) instead of cherry-picking individual files.

**Problem 2: Wrong default credentials.** The commonly-cited `admin/admin` login doesn't work on this version. The real credentials are set via environment variables inside `docker-compose.yml` itself (`INDEXER_USERNAME` / `INDEXER_PASSWORD`) — worth checking the actual deployment config rather than trusting generic documentation.

**Problem 3 (the big one): Wazuh's logcollector does not ingest a file's existing history.** This is the most important technical finding of this project. When logcollector first discovers a file to monitor, it jumps straight to the current end of that file and only forwards content appended *after* that point — a deliberate design choice to prevent an agent from flooding the pipeline with years of old log history on first install. For a **static, historical file** (like an existing Suricata capture from a completed test), this means nothing ever gets ingested, no matter how long you wait or how many times you restart the agent.

**The fix:** make historical content look like new, live-appended data — empty the monitored files, let the agent register them at a zero-byte starting position, then append the real content back in. This is a legitimate technique for backfilling a SIEM with pre-existing evidence, not a hack specific to this lab; anyone ingesting historical logs into a fresh Wazuh deployment will hit this same wall.

### Verification: real data, confirmed at the source

Rather than trust the dashboard's summary view (which aggregates dozens of default host-monitoring rules and can bury a specific event), I verified ingestion by querying the Wazuh manager's own `alerts.json` directly:

```
docker exec single-node-wazuh.manager-1 grep '"groups":["ids","suricata"]' /var/ossec/logs/alerts/2026/Sep/ossec-alerts-15.json
```

This confirmed the real Modbus write alert — full protocol detail intact (function code, register address, write value) — had been correctly parsed and stored by Wazuh, with the correct source file path attached.

**A secondary finding worth naming:** of 1,634 total lines in the original Suricata capture, only **one** line was a true `event_type: alert`. The rest was flow and traffic metadata. This is an accurate reflection of real detection work — most captured traffic is routine; the signal is a small fraction of the noise, which is exactly the triage problem this project's second half addresses.

---

## Part 2: AI-Assisted Triage

**Goal:** send the real, verified alert to an LLM for triage — severity classification, plain-English summary, recommended action — then check the output against what I already know actually happened, rather than accepting it at face value.

### A deliberate pivot: API key → local model

The original plan used the Claude API directly. In practice, Anthropic Console billing failed to process payment repeatedly — a documented, known issue affecting some international billing regions, not a problem specific to this setup. Rather than lose more time chasing a third-party billing system, I pivoted to **Ollama running Llama 3.1 locally** — same structured prompt, same real alert data, processed entirely on local hardware with no external dependency or cost.

**This is a legitimate architectural choice, not just a workaround worth mentioning once:** a fully local LLM triage layer has real advantages for a security context specifically — no alert data leaves the network to a third-party API, which matters when the alert itself might contain sensitive information about internal systems. I'd frame this as the more defensible default for a genuinely sensitive SOC environment, with a cloud API as the faster-to-deploy alternative when data sensitivity is less of a concern.

### The real alert sent for triage

```json
{
  "rule": {"description": "Suricata: Alert - Unauthorized Modbus write attempt to field device"},
  "data": {
    "src_ip": "192.168.90.6", "src_port": "55858",
    "dest_ip": "192.168.95.14", "dest_port": "502",
    "alert": {"action": "allowed", "signature": "Unauthorized Modbus write attempt to field device"},
    "modbus": {"function_code": "WrSingleReg", "write": {"address": "0", "data": "99"}}
  }
}
```

### AI Output

> **Severity:** Medium
> **Summary:** An unauthorized Modbus write attempt was made to a field device from IP address 192.168.90.6 on port 55858.
> **Recommended action:** Review system logs and network traffic to identify the source, investigate further actions taken, and consider restricting Modbus port access or implementing additional authentication.

### Validation — checked against what I actually know, not taken at face value

| AI Claim | Assessment |
|---|---|
| Severity: Medium | **Debatable.** In an OT/critical-infrastructure context, an unauthorized write to a field device controlling physical process state typically warrants **High** under IEC 62443-aligned thinking — the model has no OT-specific weighting to know that a "Medium" IT-style severity undersells physical-safety risk. |
| "...on port 55858" | **Factual error.** `55858` is the source's ephemeral port, not a meaningful identifier. The port that actually matters is `502` — the Modbus service port on the *target* device — which the model didn't surface. |
| Recommended action | **Generically sound, but incomplete.** Reasonable advice, but it never references the specific target device (`192.168.95.14`), and critically misses that `"action":"allowed"` means **Suricata detected this without blocking it** — a distinction a real analyst response needs to state explicitly, since it changes urgency. |
| What no model could know from this alert alone | Per my own testing in [ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing), this exact write landed in the wrong Modbus memory space (Holding Register vs. Input Register) and never altered the real sensor value — a fact only knowable from hands-on protocol testing, not from the alert payload. |

**Why this validation matters more than a clean result would have:** an AI triage demo that "just works" proves nothing except that a model can produce plausible-sounding text. Catching a real factual error (the wrong port) and a real omission (detection vs. blocking) is what demonstrates the actual, necessary skill — knowing when to trust AI output and when to override it with domain expertise. That's the real thesis behind "AI-assisted," not "AI-replaced," triage.

---

## What This Project Demonstrates

A complete SOC pipeline — detection, ingestion, and AI-assisted triage — built and debugged from real infrastructure problems rather than a clean tutorial path, including a documented, reusable fix for a genuine Wazuh gotcha (historical-file ingestion) that isn't well covered in standard documentation. The AI triage layer is evaluated critically, not celebrated uncritically — with specific, named errors in the model's output rather than a vague "worked well" summary.

## Portfolio Connections

| This project | Relationship |
|---|---|
| [ics-modbus-attack-testing](https://github.com/carmelin-neto/ics-modbus-attack-testing) | Source of the real Suricata detection data ingested here |
| [ot-incident-response-scenario](https://github.com/carmelin-neto/ot-incident-response-scenario) | Same underlying attack; this project adds the AI-assisted triage step ahead of that response process |
| [waf-deployment-lab](https://github.com/carmelin-neto/waf-deployment-lab) | Same pattern of naming real infrastructure constraints honestly (Cloudflare's zone requirement there, Wazuh's ingestion behavior and Anthropic billing here) rather than hiding them |
