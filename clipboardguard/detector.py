# clipboardguard/detector.py
import regex as re
from .config import PATTERNS

# compile patterns for speed
COMPILED = {}
for key, pat_list in PATTERNS.items():
    COMPILED[key] = [re.compile(p) for p in pat_list]

def find_sensitive_matches(text: str):
    """
    Returns list of tuples (pattern_type, matched_text)
    """
    matches = []
    if not text:
        return matches
    for ptype, compiled_list in COMPILED.items():
        for cre in compiled_list:
            for m in cre.finditer(text):
                matches.append((ptype, m.group(0)))
    return matches

def is_suspicious_change(prev_text: str, new_text: str):
    """
    Heuristic:
    - If prev_text contained a sensitive pattern, and new_text contains a different sensitive string of the same type,
      consider it suspicious.
    - Or if new_text contains sensitive pattern but prev_text didn't (could be paste of sensitive but not necessarily hijack).
    """
    prev_matches = find_sensitive_matches(prev_text)
    new_matches = find_sensitive_matches(new_text)

    if not new_matches:
        return False, []

    # if prev had matches but different content -> suspicious replacement
    if prev_matches:
        # create sets of matched strings for comparison
        prev_set = set((t for _, t in prev_matches))
        new_set = set((t for _, t in new_matches))
        if prev_set != new_set:
            return True, new_matches

    # If new contains sensitive data but prev did not, we flag -> returns True (user pasted sensitive)
    # For MVP we will treat this as suspicious to be safe; later add heuristics or user prompts.
    if not prev_matches and new_matches:
        return True, new_matches

    return False, new_matches
