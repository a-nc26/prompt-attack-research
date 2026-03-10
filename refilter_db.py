#!/usr/bin/env python3
"""
refilter_db.py
--------------
Re-applies a strict adversarial relevance gate to ALL entries in master_db.json,
re-classifies taxonomy, severity, and rebuilds the database in place.

Classifier v3 rules:
  Rule 1: Exclude ALL benign "act as" prompts (only keep adversarial ones)
  Rule 2: has_actual_prompt = True ONLY for literal copy-paste prompts
  Rule 3: Dedup by content hash only (no fuzzy matching)
  Rule 4: Language detection on every entry

Usage:
    python3 refilter_db.py
"""

import json
import os
import re
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Prompt extraction (mirrors classify_posts.py logic, 5000 char limit)
# ---------------------------------------------------------------------------

def extract_prompt(selftext: str):
    """
    Extract the most representative prompt text from selftext.
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


def _looks_truncated(prompt: str) -> bool:
    """
    Return True if the prompt appears to be cut off mid-word or mid-sentence
    (i.e., ends without terminal punctuation and last char is alphanumeric or a comma).
    """
    if not prompt:
        return False
    stripped = prompt.rstrip()
    if not stripped:
        return False
    last_char = stripped[-1]
    # Ends properly if it has a terminal punctuation mark
    if last_char in '.!?"\')]}':
        return False
    # Looks truncated if it ends with a word character or comma
    return bool(re.search(r'[\w,]$', stripped))

DATA_DIR        = os.path.expanduser("~/ai_security_research/data")
MASTER_DB_PATH  = os.path.join(DATA_DIR, "master_db.json")

# ===========================================================================
# RULE 1: Adversarial "act as" detection
# ===========================================================================
# An "act as" / "you are" / "pretend to be" prompt is ONLY adversarial if it
# contains at least ONE of these adversarial signals.

_ACT_AS_PATTERN = re.compile(
    r'(act as|you are|pretend to be|pretend you are|imagine you are|roleplay as|respond as|reply as|answer as)',
    re.IGNORECASE,
)

RESTRICTION_REMOVAL_SIGNALS = [
    "no restrictions", "no limits", "no boundaries", "no guidelines",
    "without restrictions", "without limits", "without filters",
    "without guidelines", "bypass", "unrestricted", "unfiltered",
    "uncensored", "unaligned", "no safety", "remove safety",
    "disable safety", "safety off", "guardrails off", "no guardrails",
]

UNETHICAL_SIGNALS = [
    "unethical", "amoral", "immoral", "no morals", "no ethics",
    "evil", "harmful", "dangerous", "illegal", "malicious",
    "nefarious", "sinister",
]

KNOWN_JAILBREAK_PERSONAS = [
    "DAN", "STAN", "DUDE", "AIM", "JAILBREAK", "ENI", "LIME", "Neptune",
    "Lyra", "MAX", "Developer Mode", "Sigma", "APOPHIS", "AntiGPT",
    "BetterDAN", "KEVIN", "JailBreak", "BasedGPT", "UnGPT", "OMEGA",
]

# Pre-compile persona patterns for exact word match (case-insensitive)
_PERSONA_WORD_PATTERNS = [
    re.compile(r'\b' + re.escape(name) + r'\b', re.IGNORECASE)
    for name in KNOWN_JAILBREAK_PERSONAS
]

INSTRUCTION_OVERRIDE_SIGNALS = [
    "ignore previous", "ignore all", "forget your training",
    "forget your instructions", "disregard your", "override your",
    "new instructions", "supersede", "overwrite your programming",
    "ignore your programming",
]


def is_adversarial_act_as(text: str) -> bool:
    """
    Rule 1: Return True if text contains an "act as" / "you are" / "pretend"
    pattern AND at least one adversarial signal. Return False if the prompt
    is benign (no adversarial signals).

    If the text does NOT contain any act-as pattern at all, return None
    (meaning this rule does not apply and other rules should decide).
    """
    if not text:
        return None

    if not _ACT_AS_PATTERN.search(text):
        return None  # Not an act-as prompt; let other rules decide

    low = text.lower()

    # Check restriction removal signals
    if any(sig in low for sig in RESTRICTION_REMOVAL_SIGNALS):
        return True

    # Check unethical/harmful signals
    if any(sig in low for sig in UNETHICAL_SIGNALS):
        return True

    # Check known jailbreak persona names (exact word match)
    for pat in _PERSONA_WORD_PATTERNS:
        if pat.search(text):
            return True

    # Check instruction override signals
    if any(sig in low for sig in INSTRUCTION_OVERRIDE_SIGNALS):
        return True

    # No adversarial signals found => benign act-as prompt
    return False


# ===========================================================================
# RULE 2: Literal prompt detection
# ===========================================================================

def is_literal_prompt(text):
    """
    Return True only if text looks like a literal copy-paste prompt that you
    could paste into ChatGPT/Claude. Discussions, blog posts, academic
    descriptions, and questions are NOT literal prompts.
    """
    if not text or len(text) < 20:
        return False
    t = text.strip()
    tl = t.lower()

    # --- NOT a literal prompt: natural prose / discussion / questions ---
    # First person narrative -> discussing a technique, not the prompt itself
    not_prompt_starters = [
        'i ', 'we ', 'my ', "i've ", "i'm ", 'been ', "i'd ",
        # Third person narrative
        'this ', 'the ', 'there ', 'it ', 'these ', 'those ',
        'here ', 'so ', 'just ', 'new ',
        # Questions
        'has ', 'does ', 'can ', 'how ', 'what ', 'why ',
        'is ', 'are ', 'did ', 'do ', 'would ', 'could ',
        'anyone ', 'has anyone', 'does anyone',
    ]
    if any(tl.startswith(s) for s in not_prompt_starters):
        return False

    # --- IS a literal prompt ---
    # Starts with imperative/second person directed at AI
    prompt_starters = [
        'you are ', 'you ', 'act as ', 'act ', 'ignore ', 'forget ',
        'pretend ', 'from now on ', 'from ', 'do not ', 'generate ',
        'write ', 'i want you to ', 'i need you to ',
        'your task is ', 'you must ', 'you will ', 'you shall ',
        'you should ', 'in this conversation ', 'for this conversation ',
        'respond as ', 'reply as ', 'answer as ',
        'simulate ', 'emulate ', 'mimic ',
        'hello chatgpt', 'hi chatgpt', 'hey chatgpt',
        'hello gpt', 'dear chatgpt',
    ]
    if any(tl.startswith(s) for s in prompt_starters):
        return True

    # System markers -> definitely a prompt
    system_markers = ['[system]', '[inst]', '### system', '<<sys>>', '###', 'system:']
    if any(tl.startswith(s) for s in system_markers):
        return True

    # Contains system/user/assistant markers (multi-turn format)
    if '[system]' in tl or '[user]' in tl or '### instruction' in tl:
        return True

    # Text in code blocks or after prompt labels was already extracted;
    # if we reach here and it has multi-paragraph imperative structure, keep it
    if t.count('\n') >= 3 and any(kw in tl for kw in ['you are', 'act as', 'ignore', 'pretend', 'from now on']):
        return True

    return False


# ===========================================================================
# RULE 4: Language detection
# ===========================================================================

def detect_language(text):
    """Simple language detection based on character ranges and common words."""
    if not text or len(text) < 10:
        return "unknown"

    sample = text[:500].lower()

    # Check character ranges
    cjk_count = sum(1 for c in sample if '\u4e00' <= c <= '\u9fff')
    cyrillic_count = sum(1 for c in sample if '\u0400' <= c <= '\u04ff')
    arabic_count = sum(1 for c in sample if '\u0600' <= c <= '\u06ff')
    hangul_count = sum(1 for c in sample if '\uac00' <= c <= '\ud7af')
    devanagari_count = sum(1 for c in sample if '\u0900' <= c <= '\u097f')
    thai_count = sum(1 for c in sample if '\u0e00' <= c <= '\u0e7f')
    japanese_count = sum(1 for c in sample if '\u3040' <= c <= '\u30ff')

    total_chars = len(sample)

    if cjk_count / total_chars > 0.1:
        if japanese_count > 0:
            return "ja"
        return "zh"
    if cyrillic_count / total_chars > 0.1:
        return "ru"
    if arabic_count / total_chars > 0.1:
        return "ar"
    if hangul_count / total_chars > 0.1:
        return "ko"
    if devanagari_count / total_chars > 0.1:
        return "hi"
    if thai_count / total_chars > 0.1:
        return "th"

    # European language detection by common words
    spanish_words = ['el ', 'la ', 'los ', 'las ', 'que ', 'del ', 'por ', 'para ', 'como ', 'esta ']
    french_words = ['le ', 'la ', 'les ', 'des ', 'est ', 'que ', 'pour ', 'dans ', 'une ', 'avec ']
    german_words = ['der ', 'die ', 'das ', 'und ', 'ist ', 'ein ', 'eine ', 'nicht ', 'mit ', 'auf ']
    portuguese_words = ['que ', 'não ', 'para ', 'com ', 'uma ', 'por ', 'mais ', 'como ', 'seu ']
    vietnamese_words = ['của ', 'và ', 'các ', 'cho ', 'một ', 'này ', 'trong ', 'được ', 'là ']

    es_score = sum(1 for w in spanish_words if w in sample)
    fr_score = sum(1 for w in french_words if w in sample)
    de_score = sum(1 for w in german_words if w in sample)
    pt_score = sum(1 for w in portuguese_words if w in sample)
    vi_score = sum(1 for w in vietnamese_words if w in sample)

    scores = {'es': es_score, 'fr': fr_score, 'de': de_score, 'pt': pt_score, 'vi': vi_score}
    best = max(scores, key=scores.get)
    if scores[best] >= 3:
        return best

    return "en"


# ---------------------------------------------------------------------------
# HARD KEEP signals -- any one present in selftext => candidate for keep
# ---------------------------------------------------------------------------

JAILBREAK_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "you are now",
    "act as if you have no",
    "you have no restrictions",
    "forget your training",
    "disregard your",
    "override your",
    "pretend you have no",
    "dan",
    "do anything now",
    "developer mode",
    "jailbreak mode",
    "unrestricted mode",
]

PERSONA_INJECTION_PATTERN = re.compile(
    r"act as\s+(an?\s+)?(AI|assistant|model|GPT|Claude|LLM|bot|expert|hacker|evil|uncensored|unfiltered|unaligned)",
    re.IGNORECASE,
)

SYSTEM_OVERRIDE_PHRASES = [
    "[system]",
    "[inst]",
    "### system:",
    "<<sys>>",
    "system prompt:",
    "ignore your previous",
    "new persona:",
    "you are an ai that",
]

ENCODING_TRICK_PATTERN = re.compile(
    r"(base64|rot13|leetspeak|pig latin|morse code).{0,80}(encode|decode|prompt)",
    re.IGNORECASE | re.DOTALL,
)
ENCODING_KEYWORD_DIRECT = [
    "base64",
    "rot13",
    "leetspeak",
    "pig latin",
]

EXTRACTION_PHRASES = [
    "repeat your instructions",
    "what is your system prompt",
    "reveal your instructions",
    "print your prompt",
    "output your system",
    "leak your",
]

EXTRACTION_PATTERNS = re.compile(
    r"(leaked?\s+(the\s+)?system\s+prompt|system\s+prompt\s+(leak|extract|dump|reveal|exfil))",
    re.IGNORECASE,
)

MULTI_TURN_PHRASES = [
    "crescendo",
    "gradually escalate",
    "each turn",
    "build up to",
]

INJECTION_PHRASES = [
    "prompt injection",
    "indirect injection",
    "ignore the above",
    "ignore above instructions",
]

RESEARCH_PHRASES = [
    "red team",
    "red-team",
    "adversarial prompt",
    "jailbreak technique",
    "safety bypass",
    "guardrail bypass",
    "prompt attack",
    "llm vulnerability",
    "jailbreak evaluation",
    "attack success rate",
]

# ---------------------------------------------------------------------------
# HARD EXCLUDE signals -- any one present => exclude (overrides KEEP)
# ---------------------------------------------------------------------------

SEO_MARKETING_PHRASES = [
    "seo",
    "meta title",
    "meta description",
    "keyword research",
    "outrank",
    "targetlanguage",
    "promptpackage",
    "prompthint",
    "redbubble",
    "etsy",
    "ecommerce",
    "e-commerce",
    "product description",
    "click-through rate",
    "conversion rate",
]

PLATFORM_NOISE_PHRASES = [
    "or is down",
    "app not working",
    "server error",
    "can't login",
    "cannot login",
]

BENIGN_START_PATTERN = re.compile(
    r"^(Write a|Create a|Generate a|Summarize|Translate)\s",
    re.IGNORECASE,
)

# Adversarial indicators needed to rescue a benign-start entry
ADVERSARIAL_RESCUE_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "you are now",
    "act as if you have no",
    "you have no restrictions",
    "forget your training",
    "disregard your",
    "override your",
    "pretend you have no",
    "dan",
    "do anything now",
    "developer mode",
    "jailbreak mode",
    "unrestricted mode",
    "base64",
    "rot13",
    "leetspeak",
    "repeat your instructions",
    "what is your system prompt",
    "reveal your instructions",
    "print your prompt",
    "output your system",
    "leak your",
    "crescendo",
    "gradually escalate",
    "prompt injection",
    "indirect injection",
    "ignore the above",
    "ignore above instructions",
    "red team",
    "red-team",
    "adversarial prompt",
    "jailbreak technique",
    "safety bypass",
    "guardrail bypass",
    "[system]",
    "[inst]",
    "### system:",
    "<<sys>>",
    "system prompt:",
    "new persona:",
    "you are an ai that",
]


# ---------------------------------------------------------------------------
# TAXONOMY CLASSIFICATION
# ---------------------------------------------------------------------------

TAXONOMY_SIGNALS = {
    "Role & Persona Manipulation": [
        "act as",
        "you are now",
        "dan",
        "persona",
        "pretend to be",
        "you have no restrictions",
        "unrestricted",
        "developer mode",
        "new persona",
    ],
    "Instruction Hierarchy Attacks": [
        "ignore previous",
        "ignore all",
        "override",
        "forget your",
        "disregard",
        "new instructions",
        "supersede",
        "[system]",
        "<<sys>>",
    ],
    "Encoding & Obfuscation": [
        "base64",
        "rot13",
        "leetspeak",
        "encode",
        "cipher",
        "obfuscat",
        "pig latin",
    ],
    "Fictional Framing": [
        "hypothetically",
        "in a story",
        "fictional world",
        "imagine a scenario",
        "creative writing exercise",
    ],
    "Social Engineering": [
        "my life depends",
        "emergency",
        "i'll be fired",
        "please i need",
        "trust me",
        "i'm a doctor",
        "i'm a researcher",
        "for educational purposes only",
    ],
    "Divide & Conquer / Multi-turn": [
        "crescendo",
        "multi-turn",
        "gradually",
        "each step",
        "build up",
        "across turns",
    ],
    "Indirect & Prompt Injection": [
        "prompt injection",
        "indirect injection",
        "ignore the above",
        "injected via",
        "tool call",
        "via document",
    ],
    "Model Extraction": [
        "repeat your instructions",
        "system prompt",
        "reveal your",
        "what were you told",
        "print your",
        "leak your",
        "your initial prompt",
    ],
    "Defense & Red-team Research": [
        "red team",
        "red-team",
        "adversarial",
        "safety evaluation",
        "jailbreak detection",
        "guardrail",
        "robustness",
        "attack success",
    ],
}

# Priority order for taxonomy (first match wins)
TAXONOMY_ORDER = [
    "Instruction Hierarchy Attacks",
    "Role & Persona Manipulation",
    "Encoding & Obfuscation",
    "Fictional Framing",
    "Social Engineering",
    "Divide & Conquer / Multi-turn",
    "Indirect & Prompt Injection",
    "Model Extraction",
    "Defense & Red-team Research",
]


def classify_taxonomy(selftext: str) -> str:
    """Return the best-matching taxonomy category for the given text."""
    low = selftext.lower() if selftext else ""
    for cat in TAXONOMY_ORDER:
        signals = TAXONOMY_SIGNALS[cat]
        if any(sig in low for sig in signals):
            return cat
    return "Role & Persona Manipulation"  # default for jailbreak content


def classify_severity(taxonomy_category: str, selftext: str) -> str:
    """Assign severity based on taxonomy and presence of actual prompt text."""
    if taxonomy_category == "Defense & Red-team Research":
        return "Info"
    if taxonomy_category in ("Role & Persona Manipulation", "Instruction Hierarchy Attacks"):
        # Check if it looks like an actual prompt (not just a named technique)
        low = (selftext or "").lower()
        # Must have actual prompt-like content
        if len(selftext or "") > 200:
            return "High"
        if any(p in low for p in ["you are now", "ignore all", "ignore previous", "act as"]):
            return "High"
        return "Medium"
    if taxonomy_category in (
        "Encoding & Obfuscation",
        "Fictional Framing",
        "Social Engineering",
        "Divide & Conquer / Multi-turn",
        "Indirect & Prompt Injection",
        "Model Extraction",
    ):
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# GATE FUNCTION (updated with Rule 1 integration)
# ---------------------------------------------------------------------------

def is_adversarial(selftext: str) -> bool:
    """
    Returns True iff selftext passes the strict adversarial relevance gate.

    Hard EXCLUDE signals override hard KEEP signals.
    Rule 1: Benign "act as" prompts are excluded.
    """
    if not selftext or not isinstance(selftext, str):
        return False

    text = selftext.strip()
    low  = text.lower()

    # ---- HARD EXCLUDE FIRST ----

    # Too short
    if len(text) < 50:
        return False

    # SEO / marketing content
    if any(phrase in low for phrase in SEO_MARKETING_PHRASES):
        return False

    # Template placeholders only (3+ occurrences with no real adversarial content)
    placeholder_count = (
        low.count("[prompt]")
        + low.count("[target]")
        + sum(1 for _ in re.finditer(r"\[variable", low))
    )
    if placeholder_count >= 3:
        # Only exclude if no real adversarial content
        has_adversarial = (
            any(p in low for p in ADVERSARIAL_RESCUE_PHRASES)
            or bool(PERSONA_INJECTION_PATTERN.search(text))
            or bool(EXTRACTION_PATTERNS.search(text))
        )
        if not has_adversarial:
            return False

    # Platform noise
    if any(phrase in low for phrase in PLATFORM_NOISE_PHRASES):
        return False

    # Auto-generated classifier descriptions that replaced real selftext in a
    # previous pipeline run -- these are NOT actual prompts.
    AUTO_DESCRIPTION_SIGNALS = [
        "unrelated to adversarial prompting",
        "not focused on adversarial prompting",
        "platform discussion covering",
        "platform technical support",
        "not an adversarial",
        "not focused on adversarial",
        "ai-generated tabletop",
        "agi timeline commentary",
        "general prompt engineering technique",
        # Classifier-generated rejection phrases that replaced real selftext
        "unrelated to llm adversarial",
        "not directly about llm adversarial",
        "not about llm adversarial",
        "not an adversarial prompt",
        "does not contain adversarial",
        "jailbreak' terminology; unrelated",
        "not directly about adversarial",
        "blue team data science",
    ]
    if any(sig in low for sig in AUTO_DESCRIPTION_SIGNALS):
        return False

    # Benign task start with no adversarial indicators
    if BENIGN_START_PATTERN.match(text):
        has_adversarial = (
            any(p in low for p in ADVERSARIAL_RESCUE_PHRASES)
            or bool(PERSONA_INJECTION_PATTERN.search(text))
            or bool(EXTRACTION_PATTERNS.search(text))
        )
        if not has_adversarial:
            return False

    # ---- RULE 1: Benign "act as" filter ----
    # If the text is an act-as prompt, only keep if adversarial signals present
    act_as_result = is_adversarial_act_as(text)
    if act_as_result is not None:
        # This IS an act-as prompt
        if act_as_result is False:
            # Benign act-as prompt => EXCLUDE
            return False
        # act_as_result is True => adversarial act-as, fall through to KEEP

    # ---- HARD KEEP SIGNALS ----

    # Explicit jailbreak phrases
    if any(phrase in low for phrase in JAILBREAK_PHRASES):
        return True

    # Persona injection pattern
    if PERSONA_INJECTION_PATTERN.search(text):
        return True

    # System override phrases
    if any(phrase in low for phrase in SYSTEM_OVERRIDE_PHRASES):
        return True

    # Encoding tricks (keyword + encode/decode/prompt nearby)
    if ENCODING_TRICK_PATTERN.search(text):
        return True
    # Direct encoding keywords that are clearly about encoding prompts
    for kw in ENCODING_KEYWORD_DIRECT:
        if kw in low and ("encode" in low or "decode" in low or "prompt" in low):
            return True

    # Extraction attempts
    if any(phrase in low for phrase in EXTRACTION_PHRASES):
        return True
    if EXTRACTION_PATTERNS.search(text):
        return True

    # Multi-turn escalation
    if any(phrase in low for phrase in MULTI_TURN_PHRASES):
        return True

    # Injection via content
    if any(phrase in low for phrase in INJECTION_PHRASES):
        return True

    # Research / defense
    if any(phrase in low for phrase in RESEARCH_PHRASES):
        return True

    return False


# ---------------------------------------------------------------------------
# MAIN LOGIC
# ---------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("refilter_db.py -- Strict Adversarial Relevance Gate (v3)")
    print("  Rule 1: Exclude benign act-as prompts")
    print("  Rule 2: Literal prompt detection for has_actual_prompt")
    print("  Rule 3: Dedup by content hash only")
    print("  Rule 4: Language detection")
    print("=" * 65)
    print()

    if not os.path.exists(MASTER_DB_PATH):
        print(f"ERROR: master_db.json not found at {MASTER_DB_PATH}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {MASTER_DB_PATH}...")
    with open(MASTER_DB_PATH, "r", encoding="utf-8") as f:
        db = json.load(f)

    total_before = len(db)
    old_relevant_count = sum(1 for e in db if e.get("relevant"))
    old_has_prompt_count = sum(1 for e in db if e.get("has_actual_prompt"))
    print(f"Total entries before: {total_before:,}")
    print(f"Relevant before:     {old_relevant_count:,}")
    print(f"has_actual_prompt before: {old_has_prompt_count:,}")
    print()

    # Track examples for reporting
    newly_excluded = []   # was relevant=True, now relevant=False
    benign_act_as_excluded = []  # specifically excluded by Rule 1
    correctly_kept = []   # relevant=True and still True with has_actual_prompt=True
    lost_has_prompt = []  # had has_actual_prompt=True before, now False

    kept_count      = 0
    excluded_count  = 0
    reextracted_count = 0
    lang_counts = Counter()

    for entry in db:
        selftext    = entry.get("selftext", "") or ""
        was_relevant = bool(entry.get("relevant"))
        entry["_old_has_prompt"] = bool(entry.get("has_actual_prompt"))
        now_relevant = is_adversarial(selftext)

        # Update relevant field
        entry["relevant"] = now_relevant

        # ---- Rule 4: Language detection ----
        lang = detect_language(selftext)
        entry["language"] = lang
        lang_counts[lang] += 1

        if now_relevant:
            # Re-classify taxonomy and severity
            new_cat = classify_taxonomy(selftext)
            entry["taxonomy_category"] = new_cat
            entry["severity"]          = classify_severity(new_cat, selftext)

            # ---- Rule 2: Literal prompt detection ----
            # Re-extract example_prompt if it is not null but looks truncated,
            # OR if it is null (try a fresh extraction).
            existing_prompt = entry.get("example_prompt")
            if existing_prompt is None or _looks_truncated(existing_prompt):
                new_prompt = extract_prompt(selftext)
                # If structured extraction found nothing, fall back to raw selftext[:5000]
                if not new_prompt and selftext:
                    new_prompt = selftext.strip()[:5000]
                if new_prompt and (existing_prompt is None or len(new_prompt) > len(existing_prompt)):
                    entry["example_prompt"] = new_prompt
                    reextracted_count += 1
            else:
                # Already have a prompt; ensure it is not capped at the old 600-char limit.
                # If selftext can yield a longer version, re-extract.
                if len(existing_prompt) >= 590:
                    new_prompt = extract_prompt(selftext)
                    # Fallback: use raw selftext if structured extraction yields nothing
                    if not new_prompt and selftext:
                        new_prompt = selftext.strip()[:5000]
                    if new_prompt and len(new_prompt) > len(existing_prompt):
                        entry["example_prompt"] = new_prompt
                        reextracted_count += 1

            # Rule 2: Set has_actual_prompt using is_literal_prompt
            ep = entry.get("example_prompt") or ""
            entry["has_actual_prompt"] = is_literal_prompt(ep)

            kept_count += 1
            if entry.get("has_actual_prompt") and len(correctly_kept) < 5:
                correctly_kept.append(entry)
            # Track entries that lost has_actual_prompt
            old_had_prompt = bool(entry.get("_old_has_prompt"))
            if old_had_prompt and not entry.get("has_actual_prompt"):
                if len(lost_has_prompt) < 5:
                    lost_has_prompt.append(entry)
        else:
            excluded_count += 1
            if was_relevant:
                if len(newly_excluded) < 5:
                    newly_excluded.append(entry)
                # Check if it was excluded specifically by Rule 1
                act_as_check = is_adversarial_act_as(selftext)
                if act_as_check is False and len(benign_act_as_excluded) < 5:
                    benign_act_as_excluded.append(entry)

    # ---- Clean up temp fields and Save ----
    for entry in db:
        entry.pop("_old_has_prompt", None)

    print(f"Saving updated master_db.json...")
    with open(MASTER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    size_bytes = os.path.getsize(MASTER_DB_PATH)

    # ---- Report ----
    new_has_prompt_count = sum(1 for e in db if e.get("relevant") and e.get("has_actual_prompt"))

    print()
    print("=" * 65)
    print("RESULTS")
    print("=" * 65)
    print(f"  1. Total entries (unchanged):       {total_before:,}")
    print(f"  2. Relevant after refilter:         {kept_count:,}  (was {old_relevant_count:,})")
    print(f"  3. has_actual_prompt=True:           {new_has_prompt_count:,}  (was {old_has_prompt_count:,})")
    print(f"     Prompts re-extracted:            {reextracted_count:,}")
    print(f"     DB file size:                    {size_bytes:,} bytes ({size_bytes / 1024 / 1024:.1f} MB)")
    print()

    # 4. Language breakdown
    print("  4. Language breakdown (all entries):")
    for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1]):
        pct = count / total_before * 100 if total_before else 0
        bar = "#" * min(40, count // max(1, total_before // 200))
        print(f"     {lang:<6} {count:>6}  ({pct:5.1f}%)  {bar}")
    print()

    # Breakdown by taxonomy (relevant only)
    cat_counts = Counter(
        e["taxonomy_category"] for e in db if e.get("relevant")
    )
    print("  Breakdown by taxonomy_category (relevant only):")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        bar = "#" * min(40, count // 20)
        print(f"    {cat:<40} {count:>5}  {bar}")
    print()

    # 5a. Lost has_actual_prompt
    lost_prompt_count = sum(
        1 for e in db
        if e.get("relevant") and not e.get("has_actual_prompt")
    )
    print(f"  5. Lost has_actual_prompt=True (descriptions, not literal prompts):")
    print(f"     {old_has_prompt_count - new_has_prompt_count:,} entries lost has_actual_prompt=True")
    if lost_has_prompt:
        print(f"     Examples:")
        for i, e in enumerate(lost_has_prompt[:5]):
            ep_preview = (e.get('example_prompt') or '')[:120]
            print(f"       [{i+1}] {(e.get('title') or '')[:60]}")
            print(f"            prompt[:120]: {ep_preview!r}")
    print()

    # 6. Examples of entries that were REMOVED (benign "act as")
    benign_act_as_count = sum(
        1 for e in db
        if not e.get("relevant") and is_adversarial_act_as(e.get("selftext", "")) is False
    )
    print("=" * 65)
    print(f"  6. Benign 'act as' prompts excluded: {benign_act_as_count:,}")
    print("     Examples of 5 entries REMOVED:")
    print("=" * 65)
    if benign_act_as_excluded:
        for i, e in enumerate(benign_act_as_excluded):
            print(f"\n  [{i+1}] Title: {(e.get('title') or '')[:80]}")
            print(f"       Category (old): {e.get('taxonomy_category', 'N/A')}")
            print(f"       Selftext[:200]: {(e.get('selftext') or '')[:200]!r}")
    else:
        # Fall back to general newly_excluded
        print("  (no benign act-as entries were previously relevant; showing general exclusions)")
        for i, e in enumerate(newly_excluded):
            print(f"\n  [{i+1}] Title: {(e.get('title') or '')[:80]}")
            print(f"       Category (old): {e.get('taxonomy_category', 'N/A')}")
            print(f"       Selftext[:200]: {(e.get('selftext') or '')[:200]!r}")

    if not benign_act_as_excluded and not newly_excluded:
        print("  (no entries newly excluded)")

    # 7. Examples of entries that CHANGED from relevant to not-relevant
    print()
    print("=" * 65)
    print(f"  7. Examples of 5 entries that CHANGED from relevant to NOT relevant:")
    print("=" * 65)
    for i, e in enumerate(newly_excluded[:5]):
        print(f"\n  [{i+1}] Title: {(e.get('title') or '')[:80]}")
        print(f"       Category (old): {e.get('taxonomy_category', 'N/A')}")
        print(f"       Selftext[:200]: {(e.get('selftext') or '')[:200]!r}")
    if not newly_excluded:
        print("  (none)")

    # 8. Examples of entries that KEPT relevant=True with has_actual_prompt=True
    print()
    print("=" * 65)
    print(f"  8. Examples of 5 entries CORRECTLY KEPT (relevant=True, has_actual_prompt=True):")
    print("=" * 65)
    for i, e in enumerate(correctly_kept[:5]):
        print(f"\n  [{i+1}] Title: {(e.get('title') or '')[:80]}")
        print(f"       Category: {e.get('taxonomy_category', 'N/A')}")
        print(f"       Severity: {e.get('severity', 'N/A')}")
        print(f"       Language: {e.get('language', 'N/A')}")
        print(f"       has_actual_prompt: {e.get('has_actual_prompt', 'N/A')}")
        print(f"       Selftext[:200]: {(e.get('selftext') or '')[:200]!r}")

    # 9. Language distribution of remaining relevant entries
    print()
    print("=" * 65)
    print("  9. Language distribution of RELEVANT entries:")
    print("=" * 65)
    relevant_lang_counts = Counter(
        e.get("language", "unknown") for e in db if e.get("relevant")
    )
    for lang, count in sorted(relevant_lang_counts.items(), key=lambda x: -x[1]):
        pct = count / kept_count * 100 if kept_count else 0
        print(f"     {lang:<6} {count:>6}  ({pct:5.1f}%)")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
