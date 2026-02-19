#!/usr/bin/env python3
"""
classify_posts.py  –  Precision Classifier (v2)
------------------------------------------------
Takes a raw Reddit JSON file path as argument and runs 4-stage classification:

  STAGE 1: Strict Relevance Gate (KEEP / EXCLUDE indicators)
  STAGE 2: Taxonomy (9 categories)
  STAGE 3: Prompt Extraction
  STAGE 4: Severity + Persona Role

Outputs:
  - master_db_v2.json  (appended, deduped, sorted newest-first)
  - /tmp/reddit_classified_YYYYMMDD.json  (today's new posts only)

Usage:
    python3 classify_posts.py <raw_json_file>
"""

import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR       = os.path.expanduser("~/ai_security_research/data")
MASTER_DB_PATH = os.path.join(DATA_DIR, "master_db_v2.json")
DATE_STR       = datetime.now().strftime("%Y%m%d")
TODAY_OUTPUT   = f"/tmp/reddit_classified_{DATE_STR}.json"


# ---------------------------------------------------------------------------
# STAGE 1 helpers – Strict Relevance Gate
# ---------------------------------------------------------------------------

KEEP_INDICATORS = {
    "prompt_patterns": [
        "```",
        "act as ",
        "you are now",
        "ignore previous instructions",
        "pretend to be",
        "[system]",
        "[user]",
        "[assistant]",
        "forget your",
        "new instructions:",
    ],
    "technique_naming": [
        "this technique",
        "this method",
        "this works by",
        "called ",
        "attack:",
        "injection:",
        "bypass:",
        "jailbreak method",
    ],
    "evidence_of_working": [
        "it said",
        "the model responded",
        "output was",
        "it worked",
        "successfully bypassed",
    ],
    "research_language": [
        "red team",
        "adversarial",
        "safety bypass",
        "vulnerability",
        "security research",
        "attack vector",
    ],
}

EXCLUDE_INDICATORS = {
    "platform_noise": [
        "or is down",
        "app not working",
        "server down",
        "error code",
        "bug report",
        "can't login",
        "not loading",
        "anyone else getting",
        "is it just me",
    ],
    "reaction_posts": [
        "lol",
        "lmao",
        "omg",
        "wow",
        "look at this",
        "mind blown",
        "crazy",
    ],
    "asking_posts": [
        "does anyone have",
        "can someone share",
        "looking for a jailbreak",
        "need a jailbreak",
        "where can i find",
    ],
    "platform_tool_posts": [
        "character card",
        "character creation",
        "lorebook",
        "world info",
        "tavern setup",
        "api connection",
        "model not loading",
    ],
    "general_discussion": [
        "what model is best",
        "gpt vs claude",
        "just got access to",
    ],
}


def passes_relevance_gate(title: str, selftext: str) -> bool:
    """STAGE 1: Return True only if the post passes the strict relevance gate."""
    combined_lower = (title + " " + selftext).lower()

    # --- Check EXCLUDE indicators first ---
    for group_indicators in EXCLUDE_INDICATORS.values():
        for indicator in group_indicators:
            if indicator in combined_lower:
                # Reaction posts: also require short body
                if indicator in ("lol", "lmao", "omg", "wow", "look at this", "mind blown", "crazy"):
                    if len(selftext.strip()) < 100:
                        return False
                else:
                    return False

    # --- Check KEEP indicators ---
    for indicator in KEEP_INDICATORS["prompt_patterns"]:
        if indicator.lower() in combined_lower:
            return True

    for indicator in KEEP_INDICATORS["technique_naming"]:
        if indicator.lower() in combined_lower:
            return True

    for indicator in KEEP_INDICATORS["evidence_of_working"]:
        if indicator.lower() in combined_lower:
            return True

    for indicator in KEEP_INDICATORS["research_language"]:
        if indicator.lower() in combined_lower:
            return True

    # Structural keep: long selftext with prompt-like content
    if len(selftext) > 200:
        prompt_like = [
            "you are ",
            "act as",
            "system:",
            "user:",
            "assistant:",
            "[system]",
            "ignore ",
            "forget ",
            "pretend",
        ]
        for pat in prompt_like:
            if pat.lower() in combined_lower:
                return True

    return False


# ---------------------------------------------------------------------------
# STAGE 2 – Taxonomy (9 categories)
# ---------------------------------------------------------------------------

TAXONOMY = [
    {
        "category": "Role & Persona Manipulation",
        "keywords": [
            "act as", "you are now", "dan", "persona", "character mode",
            "neptune", "eni", "pretend to be", "roleplay as",
            "you have no restrictions", "unrestricted",
        ],
        "severity": "High",
    },
    {
        "category": "Instruction Hierarchy Attacks",
        "keywords": [
            "ignore previous", "ignore all instructions", "override system",
            "forget your instructions", "new priority", "system prompt override",
            "disregard",
        ],
        "severity": "High",
    },
    {
        "category": "Encoding & Obfuscation",
        "keywords": [
            "base64", "leet", "rot13", "unicode", "token split", "cipher",
            "encode", "obfuscat", "language switch", "pig latin",
        ],
        "severity": "Medium",
    },
    {
        "category": "Fictional Framing",
        "keywords": [
            "fictional", "hypothetically", "in a story", "write a story where",
            "creative writing", "novel scenario", "imagine a world",
            "fiction bypass",
        ],
        "severity": "Medium",
    },
    {
        "category": "Social Engineering",
        "keywords": [
            "emotional manipul", "authority", "urgency", "guilt",
            "empathy exploit", "my life depends", "emergency",
            "please i need", "trust me",
        ],
        "severity": "Medium",
    },
    {
        "category": "Divide & Conquer / Multi-turn",
        "keywords": [
            "divide and conquer", "crescendo", "multi-turn", "gradual escalat",
            "across turns", "fragment", "split request", "step by step escalat",
        ],
        "severity": "High",
    },
    {
        "category": "Indirect & Prompt Injection",
        "keywords": [
            "prompt injection", "indirect injection", "tool injection", "rag",
            "document inject", "pdf inject", "via tool", "injected via",
        ],
        "severity": "Medium",
    },
    {
        "category": "Model Extraction",
        "keywords": [
            "system prompt", "extract", "leaked", "reveal your instructions",
            "what were you told", "repeat your", "capability prob",
            "training data",
        ],
        "severity": "Medium",
    },
    {
        "category": "Defense & Red-team Research",
        "keywords": [
            "red team", "defense", "detector", "robustness",
            "adversarial training", "safety eval", "guardrail",
            "jailbreak detect", "security research", "vulnerability research",
        ],
        "severity": "Info",
    },
]


def classify_taxonomy(title: str, selftext: str) -> dict:
    """STAGE 2: Match post against taxonomy and return category + base severity."""
    combined_lower = (title + " " + selftext).lower()

    for entry in TAXONOMY:
        for kw in entry["keywords"]:
            if kw.lower() in combined_lower:
                return {
                    "taxonomy_category": entry["category"],
                    "base_severity": entry["severity"],
                }

    return {
        "taxonomy_category": "Other/Unclassified",
        "base_severity": "Info",
    }


# ---------------------------------------------------------------------------
# STAGE 3 – Prompt Extraction
# ---------------------------------------------------------------------------

def extract_prompt(selftext: str):
    """
    STAGE 3: Extract the most representative prompt text from selftext.
    Returns a string (up to 5000 chars) or None.

    Hierarchy:
      1. Code blocks (```)
      2. Blockquotes (lines starting with >)
      3. After prompt labels (Prompt:, Template:, System:, etc.)
      4. Post body IS the prompt (starts with prompt-like text)
    """
    if not selftext:
        return None

    # 1. Code blocks
    code_blocks = re.findall(r'```(?:\w+\n)?(.*?)```', selftext, re.DOTALL)
    if code_blocks:
        longest = max(code_blocks, key=len).strip()
        if len(longest) > 20:
            return longest[:5000]

    # 2. Blockquotes
    quote_lines = [l[1:].strip() for l in selftext.split('\n') if l.startswith('>')]
    if quote_lines and len(' '.join(quote_lines)) > 30:
        return ' '.join(quote_lines)[:5000]

    # 3. After prompt labels
    for label in ['Prompt:', 'Template:', 'System:', 'Try this:', 'Copy this:', 'Instruction:']:
        if label.lower() in selftext.lower():
            idx = selftext.lower().index(label.lower()) + len(label)
            snippet = selftext[idx:idx + 5000].strip()
            if len(snippet) > 20:
                return snippet

    # 4. Post body IS the prompt (starts with prompt-like text)
    stripped = selftext.strip()
    prompt_starters = ['you are ', 'act as ', 'ignore ', 'forget ', '[system]', 'i want you to']
    if any(stripped.lower().startswith(s) for s in prompt_starters):
        return stripped[:5000]

    return None


# ---------------------------------------------------------------------------
# STAGE 4 – Severity + Persona Role
# ---------------------------------------------------------------------------

HIGH_WITH_PROMPT_CATEGORIES = {
    "Role & Persona Manipulation",
    "Instruction Hierarchy Attacks",
    "Divide & Conquer / Multi-turn",
}

MEDIUM_CATEGORIES = {
    "Encoding & Obfuscation",
    "Fictional Framing",
    "Social Engineering",
    "Indirect & Prompt Injection",
    "Model Extraction",
}


def compute_severity(taxonomy_category: str, has_actual_prompt: bool, base_severity: str) -> str:
    """
    STAGE 4 severity rules:
      - High: Role & Persona Manipulation, Instruction Hierarchy Attacks,
              Divide & Conquer / Multi-turn  AND has actual prompt text
      - Medium: Encoding & Obfuscation, Fictional Framing, Social Engineering,
                Indirect & Prompt Injection, Model Extraction
      - Low: named technique explained without prompt text (High category, no prompt)
      - Info: Defense & Red-team Research
    """
    if taxonomy_category == "Defense & Red-team Research":
        return "Info"
    if taxonomy_category == "Other/Unclassified":
        return "Info"
    if taxonomy_category in HIGH_WITH_PROMPT_CATEGORIES:
        if has_actual_prompt:
            return "High"
        else:
            return "Low"
    if taxonomy_category in MEDIUM_CATEGORIES:
        return "Medium"
    return base_severity


def extract_persona(text: str):
    """STAGE 4: Extract persona/role name from text using regex patterns."""
    patterns = [
        r'act as (?:an? )?([A-Za-z0-9 \-_]+)',
        r'you are (?:now )?(?:an? )?([A-Za-z0-9 \-_]+)',
        r'pretend to be (?:an? )?([A-Za-z0-9 \-_]+)',
        r'\b(DAN|STAN|DUDE|AIM|JAILBREAK|ENI|LIME|Neptune|Lyra|MAX)\b',
    ]
    SKIP_ROLES = {'the', 'a', 'an', 'able', 'allowed'}
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            role = m.group(1).strip()[:50]
            if len(role) > 1 and role.lower() not in SKIP_ROLES:
                return role
    return None


# ---------------------------------------------------------------------------
# Technique name / description derivation
# ---------------------------------------------------------------------------

CATEGORY_TECHNIQUE_DEFAULTS = {
    "Role & Persona Manipulation":    ("Persona Override",               "Attempts to override model identity via persona assignment or character roleplay."),
    "Instruction Hierarchy Attacks":  ("Instruction Hierarchy Exploit",   "Attempts to supersede or erase prior system-level instructions."),
    "Encoding & Obfuscation":         ("Encoding-based Bypass",           "Uses character encoding, ciphers, or obfuscation to evade content filters."),
    "Fictional Framing":              ("Fictional Context Bypass",         "Wraps harmful requests inside fictional or hypothetical narratives."),
    "Social Engineering":             ("Social Engineering Manipulation",  "Leverages emotional appeals, authority claims, or urgency to elicit unsafe outputs."),
    "Divide & Conquer / Multi-turn":  ("Multi-turn Escalation",           "Gradually escalates across conversation turns to bypass accumulated safety context."),
    "Indirect & Prompt Injection":    ("Indirect Prompt Injection",        "Injects adversarial instructions via external documents, tools, or RAG content."),
    "Model Extraction":               ("System Prompt / Model Extraction", "Attempts to reveal system prompts, training data, or internal model configuration."),
    "Defense & Red-team Research":    ("Red-team / Defense Research",      "Research or tooling focused on detecting, measuring, or defending against prompt attacks."),
    "Other/Unclassified":             ("Unclassified Technique",           "No clear attack pattern matched; requires manual review."),
}


def derive_technique(title: str, taxonomy_category: str) -> tuple:
    """Return (technique_name, technique_description) based on title + category."""
    default_name, default_desc = CATEGORY_TECHNIQUE_DEFAULTS.get(
        taxonomy_category,
        ("Unknown Technique", "Classification did not match a known attack pattern.")
    )
    # Use the post title as the technique name if it's concise enough
    clean_title = title.strip()
    if 5 < len(clean_title) <= 80:
        return clean_title, default_desc
    return default_name, default_desc


# ---------------------------------------------------------------------------
# Full post processing pipeline
# ---------------------------------------------------------------------------

def process_post(raw: dict) -> dict:
    """Run all 4 stages and return the enriched post dict."""
    title    = raw.get("title", "") or ""
    selftext = raw.get("selftext", "") or ""
    created_utc = raw.get("created_utc", 0)

    # Stage 1 – Relevance gate
    relevant = passes_relevance_gate(title, selftext)

    # Stage 2 – Taxonomy
    tax = classify_taxonomy(title, selftext)
    taxonomy_category = tax["taxonomy_category"]
    base_severity     = tax["base_severity"]

    # If no category matched → mark not relevant
    if taxonomy_category == "Other/Unclassified":
        relevant = False

    # Stage 3 – Prompt extraction
    example_prompt   = extract_prompt(selftext)
    has_actual_prompt = bool(example_prompt and len(example_prompt.strip()) > 10)

    # Stage 4 – Severity + persona
    severity    = compute_severity(taxonomy_category, has_actual_prompt, base_severity)
    persona_role = extract_persona(title + " " + selftext)

    # Technique name / description
    technique_name, technique_description = derive_technique(title, taxonomy_category)

    # Human-readable date
    try:
        post_date = datetime.fromtimestamp(created_utc, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        post_date = ""

    # Normalise permalink
    permalink = raw.get("permalink", "") or ""
    if permalink and not permalink.startswith("http"):
        permalink = "https://www.reddit.com" + permalink

    return {
        # Original fields
        "id":                  raw.get("id", ""),
        "title":               title,
        "selftext":            selftext[:5000],
        "author":              raw.get("author", ""),
        "subreddit":           raw.get("subreddit", ""),
        "permalink":           permalink,
        "url":                 raw.get("url", "") or "",
        "score":               int(raw.get("score", 0) or 0),
        "num_comments":        int(raw.get("num_comments", 0) or 0),
        "created_utc":         created_utc,
        "post_date":           post_date,
        # New precision fields
        "relevant":            relevant,
        "taxonomy_category":   taxonomy_category,
        "technique_name":      technique_name,
        "technique_description": technique_description,
        "example_prompt":      example_prompt,
        "persona_role":        persona_role,
        "severity":            severity,
        "has_actual_prompt":   has_actual_prompt,
        "classified_at":       datetime.now(tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 classify_posts.py <raw_json_file>", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"ERROR: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    # Load raw posts
    with open(input_file, "r", encoding="utf-8") as f:
        try:
            raw_posts = json.load(f)
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse input JSON: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Loaded {len(raw_posts)} raw posts from {input_file}")

    # Load or initialise master DB (v2)
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(MASTER_DB_PATH):
        with open(MASTER_DB_PATH, "r", encoding="utf-8") as f:
            try:
                master_db = json.load(f)
            except json.JSONDecodeError:
                print("WARN: master_db_v2.json is corrupt – starting fresh.", file=sys.stderr)
                master_db = []
    else:
        master_db = []

    print(f"Master DB (v2) currently has {len(master_db)} posts")

    # Build dedup index by permalink
    known_permalinks = set()
    for post in master_db:
        pl = post.get("permalink", "")
        if pl:
            known_permalinks.add(pl)

    new_posts  = []
    duplicates = 0

    for raw in raw_posts:
        pl = raw.get("permalink", "") or ""
        if pl and not pl.startswith("http"):
            pl = "https://www.reddit.com" + pl
            raw["permalink"] = pl

        if pl in known_permalinks:
            duplicates += 1
            continue

        classified = process_post(raw)
        new_posts.append(classified)
        known_permalinks.add(pl)

    master_db.extend(new_posts)
    master_db.sort(key=lambda p: p.get("created_utc", 0), reverse=True)

    with open(MASTER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(master_db, f, indent=2, ensure_ascii=False)

    with open(TODAY_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(new_posts, f, indent=2, ensure_ascii=False)

    # --- Summary ---
    print(f"\n--- Classification Summary ---")
    print(f"  New posts added:     {len(new_posts)}")
    print(f"  Duplicates skipped:  {duplicates}")
    print(f"  Total in database:   {len(master_db)}")
    print(f"  Today's output:      {TODAY_OUTPUT}")
    print(f"  Master DB (v2):      {MASTER_DB_PATH}")

    if new_posts:
        relevant_new = [p for p in new_posts if p["relevant"]]
        cat_counts   = Counter(p["taxonomy_category"] for p in new_posts)
        sev_counts   = Counter(p["severity"] for p in new_posts)

        print(f"\n  Relevant posts: {len(relevant_new)} / {len(new_posts)}")
        print(f"\n  Category breakdown (new posts):")
        for cat, count in cat_counts.most_common():
            print(f"    {cat}: {count}")
        print(f"\n  Severity breakdown (new posts):")
        for sev in ["High", "Medium", "Low", "Info"]:
            if sev in sev_counts:
                print(f"    {sev}: {sev_counts[sev]}")


if __name__ == "__main__":
    main()
