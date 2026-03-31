# Prompt Attack Taxonomy — Automated Collection Pipeline

Automated pipeline that collects jailbreak/prompt-injection techniques from Reddit and public HuggingFace/GitHub datasets, classifies them against a taxonomy, and publishes an interactive dashboard to GitHub Pages.

**Live dashboard:** https://a-nc26.github.io/prompt-attack-taxonomy/

---

## Quick Start

### Prerequisites

- **Python 3.9+** (no pip packages needed — stdlib only)
- **bash** (macOS/Linux)
- **git** with push access to both repos:
  - `prompt-attack-research` (this repo — code + data)
  - `prompt-attack-taxonomy` (GitHub Pages dashboard)

No API keys needed — uses Reddit public JSON API and public HuggingFace datasets.

### Setup

```bash
# 1. Clone this repo
git clone https://github.com/a-nc26/prompt-attack-research.git ~/ai_security_research
cd ~/ai_security_research

# 2. Clone the GitHub Pages repo (for dashboard publishing)
git clone https://github.com/a-nc26/prompt-attack-taxonomy.git .pages_repo

# 3. Create required directories
mkdir -p logs reports data

# 4. Make scripts executable
chmod +x run_nightly.sh fetch_reddit.sh

# 5. Run the full pipeline
bash run_nightly.sh
```

That's it. The dashboard will be rebuilt and pushed to GitHub Pages.

---

## Running

```bash
# Full pipeline (fetch + classify + build dashboard + push)
bash ~/ai_security_research/run_nightly.sh

# Or run individual stages:
bash ~/ai_security_research/fetch_reddit.sh
python3 ~/ai_security_research/classify_posts.py /tmp/reddit_posts_raw_$(date +%Y%m%d).json
python3 ~/ai_security_research/build_dashboard.py

# Re-classify entire DB after taxonomy changes:
python3 ~/ai_security_research/refilter_db.py
python3 ~/ai_security_research/build_dashboard.py
```

---

## Directory Structure

```
~/ai_security_research/
├── run_nightly.sh          # Master orchestrator (runs all stages)
├── fetch_reddit.sh         # Fetch raw posts from Reddit (20 subreddits)
├── fetch_datasets.py       # Fetch HuggingFace/GitHub datasets (Mondays only)
├── classify_posts.py       # Classify and deduplicate posts
├── refilter_db.py          # Re-classify entire DB after rule changes
├── build_dashboard.py      # Generate HTML dashboard + push to Pages
├── data/
│   └── master_db.json      # Cumulative classified database (~22K entries)
├── logs/
│   └── nightly_YYYYMMDD.log
├── reports/
│   └── taxonomy_YYYYMMDD.html
└── .pages_repo/            # GitHub Pages repo (cloned in step 2)
    └── index.html
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `master_db.json` missing | Run `bash run_nightly.sh` — creates it on first run |
| `.pages_repo/` missing | `git clone https://github.com/a-nc26/prompt-attack-taxonomy.git .pages_repo` |
| Dashboard empty after push | Check `git -C .pages_repo log -1` — did the push succeed? |
| Reddit returning 0 posts | Reddit rate-limits; wait 10 min and retry |
| Want to re-classify everything | `python3 refilter_db.py` then `python3 build_dashboard.py` |
