# AI Security Research — Reddit Taxonomy Pipeline

Automated nightly pipeline that fetches Reddit posts from AI/jailbreak/security
subreddits, classifies them using a keyword-based taxonomy, stores them in a
master JSON database, and regenerates an interactive HTML dashboard.

---

## Directory Structure

```
~/ai_security_research/
├── fetch_reddit.sh         # Stage 1 — Fetch raw posts from Reddit
├── classify_posts.py       # Stage 2 — Classify and deduplicate posts
├── build_dashboard.py      # Stage 3 — Generate HTML dashboard
├── run_nightly.sh          # Master script (runs all 3 stages)
├── README.md               # This file
├── data/
│   └── master_db.json      # Cumulative classified post database (seed + all runs)
├── logs/
│   ├── fetch_YYYYMMDD.log  # Per-run fetch logs
│   └── nightly_YYYYMMDD.log# Per-run orchestration logs
└── reports/
    └── taxonomy_YYYYMMDD.html  # Dated dashboard archives
```

**External outputs:**
- `/tmp/reddit_posts_raw_YYYYMMDD.json`  — Raw fetched posts (per run)
- `/tmp/reddit_classified_YYYYMMDD.json` — Today's newly classified posts
- `~/Desktop/prompt_attack_taxonomy.html` — Always-current dashboard

---

## What Each Script Does

### `fetch_reddit.sh`
- Iterates over 20 AI/security/jailbreak subreddits
- Calls the Reddit public JSON API (`/r/<sub>/new.json?limit=50`)
- Filters posts created within the last 24 hours
- Skips subreddits that return 403 or 404 (private/banned/non-existent)
- Sleeps 2 seconds between requests to respect rate limits
- Outputs all filtered posts as a single JSON array to `/tmp/reddit_posts_raw_YYYYMMDD.json`
- Logs to `~/ai_security_research/logs/fetch_YYYYMMDD.log`

### `classify_posts.py`
- Reads the raw JSON produced by `fetch_reddit.sh`
- Loads `~/ai_security_research/data/master_db.json` (creates it if absent)
- Deduplicates by permalink — already-seen posts are skipped
- For each new post, applies keyword-based classification across 13 taxonomy categories
- Assigns severity (High / Medium / Low / Info) per category
- Extracts persona/role with regex patterns (act as, you are, DAN, etc.)
- Extracts example prompt from first code block or blockquote in selftext
- Appends new posts to master_db.json and saves
- Writes today's newly classified posts to `/tmp/reddit_classified_YYYYMMDD.json`
- Prints a summary: new posts added, duplicates skipped, total in database

### `build_dashboard.py`
- Reads the full `master_db.json`
- Generates a self-contained, dark-themed interactive HTML file (no external deps)
- Saves to `~/Desktop/prompt_attack_taxonomy.html` (overwrites on each run)
- Saves a dated archive to `~/ai_security_research/reports/taxonomy_YYYYMMDD.html`

### `run_nightly.sh`
- Master orchestrator: runs all three stages in sequence
- Logs everything to `~/ai_security_research/logs/nightly_YYYYMMDD.log`
- Designed to be called by cron

---

## Taxonomy Categories

| Category | Severity |
|---|---|
| Role & Persona Manipulation | High |
| Instruction Hierarchy Attacks | High |
| Divide & Conquer | High |
| Token & Format Exploitation | High |
| Context Manipulation | Medium |
| Encoding & Obfuscation | Medium |
| Indirect & Injection Attacks | Medium |
| Social Engineering | Medium |
| Fictional Framing | Medium |
| Model Extraction | Medium |
| Jailbreak Aggregators | Low |
| Character AI / Roleplay Tools | Low |
| Defense & Red-teaming Research | Info |

---

## Cron Setup (Nightly at 2am)

Open your crontab:

```bash
crontab -e
```

Add this line:

```
0 2 * * * bash ~/ai_security_research/run_nightly.sh
```

Save and exit. Verify with:

```bash
crontab -l
```

---

## Manual Run

Run the full pipeline immediately:

```bash
bash ~/ai_security_research/run_nightly.sh
```

Or run individual stages:

```bash
# Stage 1: Fetch
bash ~/ai_security_research/fetch_reddit.sh

# Stage 2: Classify (pass today's raw file)
python3 ~/ai_security_research/classify_posts.py /tmp/reddit_posts_raw_$(date +%Y%m%d).json

# Stage 3: Dashboard
python3 ~/ai_security_research/build_dashboard.py
```

---

## Viewing the Dashboard

Open in your browser:

```bash
open ~/Desktop/prompt_attack_taxonomy.html
```

Or navigate to the file directly in any browser.

Dashboard features:
- Stats bar: total, relevant, high/medium severity counts, subreddit count, last updated
- Left sidebar: category tree with counts — click any to filter
- Filter row: full-text search, category/severity/subreddit dropdowns, show/hide prompts toggle
- Sortable columns: severity, category, title, persona, subreddit, date, score
- Expandable descriptions and example prompts per row
- Taxonomy reference section (collapsible) at bottom

---

## Subreddits Monitored

ChatGptDAN, ClaudeAIJailbreak, GPT_jailbreaks, AITabletop, ChatGPTPromptGenius,
ChatGPTJailbreak, AIJailbreak, LocalLLaMA, PromptEngineering, JanitorAI_Official,
SillyTavernAI, PygmalionAI, HuggingFace, Artificial, GPT3, cybersecurityai,
llmsecurity, cybersecurity, maximumai, ChatGPTJailbreaks_

---

## Notes

- The Reddit public API does not require authentication for read-only access.
- User-Agent is set to `AISecurityResearch/1.0` as required by Reddit's API rules.
- The master database grows incrementally — each nightly run appends only new posts.
- Posts are sorted newest-first in the database and dashboard.
