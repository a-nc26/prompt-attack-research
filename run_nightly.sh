#!/bin/bash
# run_nightly.sh
# Master orchestration script — runs all pipeline stages in sequence.
# Intended to be called by cron at 2am daily.
#
# Cron setup:
#   crontab -e
#   0 2 * * * bash ~/ai_security_research/run_nightly.sh

DATE=$(date +%Y%m%d)
LOG_DIR="$HOME/ai_security_research/logs"
LOG="$LOG_DIR/nightly_$DATE.log"

mkdir -p "$LOG_DIR"

echo "[$(date)] Starting nightly run" >> "$LOG"

echo "[$(date)] Step 1/3 — Fetching Reddit posts..." >> "$LOG"
bash ~/ai_security_research/fetch_reddit.sh >> "$LOG" 2>&1

if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: fetch_reddit.sh failed" >> "$LOG"
fi

echo "[$(date)] Step 2/3 — Classifying posts..." >> "$LOG"
python3 ~/ai_security_research/classify_posts.py /tmp/reddit_posts_raw_$DATE.json >> "$LOG" 2>&1

if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: classify_posts.py failed" >> "$LOG"
fi

echo "[$(date)] Step 3/3 — Building dashboard..." >> "$LOG"
python3 ~/ai_security_research/build_dashboard.py >> "$LOG" 2>&1

if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: build_dashboard.py failed" >> "$LOG"
fi

echo "[$(date)] Nightly run complete" >> "$LOG"
echo "[$(date)] Dashboard: ~/Desktop/prompt_attack_taxonomy.html" >> "$LOG"
echo "[$(date)] Log: $LOG" >> "$LOG"
