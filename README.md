# The-Orchestrator
## What it does vs. what it refuses to do

**Automated (safe):**
- crt.sh + subfinder for subdomains (passive)
- nmap for port/service discovery (gated by typed confirmation)
- nuclei for non-destructive template matching (`-no-interactsh`, no OOB)
- Normalization into a single asset inventory
- Report skeleton in Markdown + JSON

**Deliberately NOT automated:**
- No exploitation. No SQLi, no auth bypass, no shell upload, no fuzzing for logic bugs.
- No "auto-pwn." That's the part that gets people arrested or banned.
- The `phase4_stop()` prints *why* — read it, it's the actual lesson.

---

## Setup & usage

```bash
# Optional but recommended external tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
# nmap from your package manager

# Passive only — totally safe, no packets to target
python orchestrator.py example.com --authorized-by "Jane Doe (RoE #123)" --skip-active

# Full pipeline — requires typing the authorization phrase
python orchestrator.py example.com --authorized-by "Jane Doe (RoE #123)"
```

**Output:** `./recon-out/recon-<target>-<timestamp>.{json,md}` — the Markdown is what you'd paste into a client report as the "Asset Inventory" section, and the `Candidates for Manual Review` table is your worklist.

---

## Why this beats a "do-everything" tool

| Your ask | What actually happens |
|---|---|
| "Find all the bugs for me" | Tool finds *candidates*. You find bugs. |
| "Save time on recon" | ✅ This genuinely does — the boring 60% is now one command. |
| "Skip the manual work" | ❌ The manual work *is* the job. That's where unique findings live. |
| "One button, done" | Programs ban it; clients fire you for it. |

The realistic professional reality: recon is ~40% of time and mostly automatable. Understanding, testing, and reporting is ~60% and mostly not. Every "one tool to do everything" you see advertised is either (a) a wrapper around the tools above, or (b) a scam.
