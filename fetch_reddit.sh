#!/bin/bash
# fetch_reddit.sh
# Fetches recent Reddit posts from AI/security-related subreddits
# Outputs: /tmp/reddit_posts_raw_YYYYMMDD.json
# Logs to: ~/ai_security_research/logs/fetch_YYYYMMDD.log

USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DATE=$(date +%Y%m%d)
OUTPUT_FILE="/tmp/reddit_posts_raw_${DATE}.json"
LOG_DIR="$HOME/ai_security_research/logs"
LOG_FILE="${LOG_DIR}/fetch_${DATE}.log"

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

SUBREDDITS=(
    "ChatGptDAN"
    "ClaudeAIJailbreak"
    "GPT_jailbreaks"
    "AITabletop"
    "ChatGPTPromptGenius"
    "ChatGPTJailbreak"
    "AIJailbreak"
    "LocalLLaMA"
    "PromptEngineering"
    "JanitorAI_Official"
    "SillyTavernAI"
    "PygmalionAI"
    "HuggingFace"
    "Artificial"
    "GPT3"
    "cybersecurityai"
    "llmsecurity"
    "cybersecurity"
    "maximumai"
    "ChatGPTJailbreaks_"
)

# Calculate unix timestamp for 24 hours ago
CUTOFF_UTC=$(python3 -c "import time; print(int(time.time()) - 86400)")

log "Starting Reddit fetch. Cutoff UTC: $CUTOFF_UTC"
log "Output file: $OUTPUT_FILE"
log "Subreddits to fetch: ${#SUBREDDITS[@]}"

# Temporary file to accumulate all posts
TEMP_COMBINED="/tmp/reddit_all_raw_$$.json"
echo "[]" > "$TEMP_COMBINED"

for sub in "${SUBREDDITS[@]}"; do
    log "Fetching r/$sub ..."

    TEMP_RESPONSE="/tmp/reddit_response_$$.json"
    HTTP_CODE=$(curl -s -o "$TEMP_RESPONSE" -w "%{http_code}" \
        -H "User-Agent: $USER_AGENT" \
        "https://www.reddit.com/r/${sub}/new.json?limit=50")

    if [ "$HTTP_CODE" = "404" ]; then
        log "SKIP r/$sub — 404 Not Found (subreddit may not exist)"
        rm -f "$TEMP_RESPONSE"
        sleep 2
        continue
    fi

    if [ "$HTTP_CODE" = "403" ]; then
        log "SKIP r/$sub — 403 Forbidden (private or banned)"
        rm -f "$TEMP_RESPONSE"
        sleep 2
        continue
    fi

    if [ "$HTTP_CODE" != "200" ]; then
        log "SKIP r/$sub — HTTP $HTTP_CODE unexpected response"
        rm -f "$TEMP_RESPONSE"
        sleep 2
        continue
    fi

    # Use Python3 to parse JSON, filter by cutoff, and merge into combined list
    python3 - <<PYEOF
import json, sys

cutoff = $CUTOFF_UTC
subreddit = "$sub"

with open("$TEMP_RESPONSE", "r", encoding="utf-8", errors="replace") as f:
    body = f.read()

try:
    data = json.loads(body)
except Exception as e:
    print(f"  [WARN] Failed to parse JSON for r/{subreddit}: {e}", file=sys.stderr)
    sys.exit(0)

posts_data = data.get("data", {}).get("children", [])
filtered = []
for child in posts_data:
    post = child.get("data", {})
    created_utc = post.get("created_utc", 0)
    if created_utc >= cutoff:
        filtered.append({
            "id":           post.get("id", ""),
            "title":        post.get("title", ""),
            "selftext":     post.get("selftext", ""),
            "author":       post.get("author", ""),
            "subreddit":    post.get("subreddit", subreddit),
            "permalink":    "https://www.reddit.com" + post.get("permalink", ""),
            "url":          post.get("url", ""),
            "score":        post.get("score", 0),
            "num_comments": post.get("num_comments", 0),
            "created_utc":  created_utc,
            "is_self":      post.get("is_self", False),
            "link_flair_text": post.get("link_flair_text", "")
        })

# Load existing combined list and append
try:
    with open("$TEMP_COMBINED", "r") as f:
        combined = json.load(f)
except Exception:
    combined = []

combined.extend(filtered)

with open("$TEMP_COMBINED", "w") as f:
    json.dump(combined, f, indent=2)

print(f"  r/{subreddit}: {len(filtered)} posts within last 24h (of {len(posts_data)} fetched)")
PYEOF

    rm -f "$TEMP_RESPONSE"

    COUNT=$(python3 -c "
import json
with open('$TEMP_COMBINED') as f:
    data = json.load(f)
print(len(data))
")
    log "  r/$sub fetched. Running total: $COUNT posts"

    sleep 2
done

# Move combined file to final output
mv "$TEMP_COMBINED" "$OUTPUT_FILE"

TOTAL=$(python3 -c "
import json
with open('$OUTPUT_FILE') as f:
    data = json.load(f)
print(len(data))
")

log "Fetch complete. Total posts collected: $TOTAL"
log "Output written to: $OUTPUT_FILE"
