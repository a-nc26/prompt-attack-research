#!/bin/bash
# run_nightly.sh
# Master orchestration script — runs all pipeline stages in sequence.
# Intended to be called by cron at 2am daily.
#
# Cron setup:
#   crontab -e
#   0 2 * * * bash ~/ai_security_research/run_nightly.sh

DATE=$(date +%Y%m%d)
DOW=$(date +%u)   # 1=Monday, 7=Sunday (ISO weekday)
LOG_DIR="$HOME/ai_security_research/logs"
LOG="$LOG_DIR/nightly_$DATE.log"

mkdir -p "$LOG_DIR"

echo "[$(date)] Starting nightly run" >> "$LOG"

# Step 0: On Mondays only, fetch Tier 1 academic datasets
if [ "$DOW" -eq 1 ]; then
    echo "[$(date)] Step 0/4 — Monday: Fetching Tier 1 academic datasets..." >> "$LOG"
    python3 ~/ai_security_research/fetch_datasets.py >> "$LOG" 2>&1
    if [ $? -ne 0 ]; then
        echo "[$(date)] ERROR: fetch_datasets.py failed" >> "$LOG"
    fi
else
    echo "[$(date)] Step 0/4 — Skipping dataset fetch (runs on Mondays only, today DOW=$DOW)" >> "$LOG"
fi

echo "[$(date)] Step 1/4 — Fetching Reddit posts..." >> "$LOG"
bash ~/ai_security_research/fetch_reddit.sh >> "$LOG" 2>&1

if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: fetch_reddit.sh failed" >> "$LOG"
fi

echo "[$(date)] Step 2/4 — Classifying posts..." >> "$LOG"
python3 ~/ai_security_research/classify_posts.py /tmp/reddit_posts_raw_$DATE.json >> "$LOG" 2>&1

if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: classify_posts.py failed" >> "$LOG"
fi

echo "[$(date)] Step 3/4 — Building dashboard..." >> "$LOG"
python3 ~/ai_security_research/build_dashboard.py >> "$LOG" 2>&1

if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: build_dashboard.py failed" >> "$LOG"
fi

echo "[$(date)] Step 4/4 — Pushing dashboard to GitHub Pages..." >> "$LOG"

PAGES_REPO="$HOME/ai_security_research/.pages_repo"

# Clone public dashboard repo if not already present
if [ ! -d "$PAGES_REPO/.git" ]; then
    git clone https://github.com/a-nc26/prompt-attack-taxonomy.git "$PAGES_REPO" >> "$LOG" 2>&1
fi

# Copy latest dashboard as index.html
cp ~/Desktop/prompt_attack_taxonomy.html "$PAGES_REPO/index.html"

# Commit and push
cd "$PAGES_REPO"
git add index.html
git commit -m "Dashboard update: $DATE nightly run" >> "$LOG" 2>&1
git push origin main >> "$LOG" 2>&1

if [ $? -eq 0 ]; then
    echo "[$(date)] Dashboard pushed to: https://a-nc26.github.io/prompt-attack-taxonomy/" >> "$LOG"
else
    echo "[$(date)] ERROR: GitHub Pages push failed" >> "$LOG"
fi

# Also commit updated master_db to private research repo
cd ~/ai_security_research
git add data/master_db.json data/master_db_v2.json
git commit -m "Data update: $DATE nightly run" >> "$LOG" 2>&1
git push origin main >> "$LOG" 2>&1

echo "[$(date)] Nightly run complete" >> "$LOG"
echo "[$(date)] Live dashboard: https://a-nc26.github.io/prompt-attack-taxonomy/" >> "$LOG"
echo "[$(date)] Log: $LOG" >> "$LOG"
