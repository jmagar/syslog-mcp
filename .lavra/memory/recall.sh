#!/bin/bash
#
# Search the knowledge base (.lavra/memory/knowledge.jsonl)
#
# Usage:
#   recall.sh "keyword"                    # Search by keyword
#   recall.sh "keyword" --type learned     # Filter by type
#   recall.sh --recent 10                  # Show latest N entries
#   recall.sh --stats                      # Knowledge base stats
#   recall.sh "keyword" --all              # Include archive
#   recall.sh --topic BD-005               # Filter by epic parent
#

MEMORY_DIR="${CLAUDE_PROJECT_DIR:-.}/.lavra/memory"
KNOWLEDGE_FILE="$MEMORY_DIR/knowledge.jsonl"
ARCHIVE_FILE="$MEMORY_DIR/knowledge.archive.jsonl"

if [[ ! -f "$KNOWLEDGE_FILE" ]]; then
  echo "No knowledge base found at $KNOWLEDGE_FILE"
  exit 0
fi

# Parse args
QUERY=""
TYPE_FILTER=""
RECENT=0
SHOW_STATS=false
INCLUDE_ARCHIVE=false
TOPIC_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "Error: --type requires a value" >&2
        exit 1
      fi
      TYPE_FILTER="$2"
      shift 2
      ;;
    --recent)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "Error: --recent requires a value" >&2
        exit 1
      fi
      RECENT="$2"
      shift 2
      ;;
    --stats) SHOW_STATS=true; shift ;;
    --all) INCLUDE_ARCHIVE=true; shift ;;
    --topic)
      if [[ -z "$2" || "$2" == --* ]]; then
        echo "Error: --topic requires a value" >&2
        exit 1
      fi
      TOPIC_ID="$2"
      shift 2
      ;;
    *) QUERY="$1"; shift ;;
  esac
done

# Validate numeric parameters
if ! [[ "$RECENT" =~ ^[0-9]+$ ]]; then
  RECENT=0
fi

# Stats mode
if $SHOW_STATS; then
  TOTAL=$(wc -l < "$KNOWLEDGE_FILE" | tr -d ' ')
  ARCHIVE_COUNT=0
  [[ -f "$ARCHIVE_FILE" ]] && ARCHIVE_COUNT=$(wc -l < "$ARCHIVE_FILE" | tr -d ' ')

  echo "Knowledge base: $KNOWLEDGE_FILE"
  echo "Active entries: $TOTAL"
  echo "Archived: $ARCHIVE_COUNT"
  echo ""
  echo "By type:"
  jq -r '.type' "$KNOWLEDGE_FILE" 2>/dev/null | sort | uniq -c | sort -rn
  echo ""
  echo "Top tags:"
  jq -r '.tags[]' "$KNOWLEDGE_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -15
  exit 0
fi

# Topic mode -- filter by bead parent
if [[ -n "$TOPIC_ID" ]]; then
  if ! command -v bd &>/dev/null; then
    echo "bd not found -- cannot query topic children"
    exit 1
  fi

  CHILDREN=$(bd list --parent "$TOPIC_ID" --json 2>/dev/null | jq -r '.[].id' 2>/dev/null)

  if [[ -z "$CHILDREN" ]]; then
    echo "No children found for topic $TOPIC_ID"
    exit 0
  fi

  for CHILD_ID in $CHILDREN; do
    grep -F "\"bead\":\"$CHILD_ID\"" "$KNOWLEDGE_FILE" 2>/dev/null
  done | jq -r '"\(.type | ascii_upcase): \(.content)"' 2>/dev/null
  exit 0
fi

# Build input: archive first so tail -N returns the newest entries from knowledge.jsonl
if $INCLUDE_ARCHIVE && [[ -f "$ARCHIVE_FILE" ]]; then
  INPUT_FILES=("$ARCHIVE_FILE" "$KNOWLEDGE_FILE")
else
  INPUT_FILES=("$KNOWLEDGE_FILE")
fi

# Recent mode
if [[ "$RECENT" -gt 0 ]]; then
  cat "${INPUT_FILES[@]}" | tail -"$RECENT" | jq -r '"\(.type | ascii_upcase): \(.content)"' 2>/dev/null
  exit 0
fi

# Search mode
if [[ -z "$QUERY" ]]; then
  echo "Usage: recall.sh \"keyword\" [--type TYPE] [--recent N] [--stats] [--all] [--topic ID]"
  exit 0
fi

# FTS5 search if available
USED_FTS5=false

if command -v sqlite3 &>/dev/null; then
  DB_PATH="$MEMORY_DIR/knowledge.db"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  JSONL_PATH="$KNOWLEDGE_FILE"

  # Auto-build DB on first use if it doesn't exist but JSONL does
  if [[ ! -f "$DB_PATH" ]] && [[ -f "$JSONL_PATH" ]] && [[ -f "$SCRIPT_DIR/knowledge-db.sh" ]]; then
    echo "Building knowledge DB from JSONL..." >&2
    # Source the library and call kb_sync directly (knowledge-db.sh only defines
    # functions; running it as a subprocess with "sync" would be a no-op).
    source "$SCRIPT_DIR/knowledge-db.sh"
    kb_sync "$DB_PATH" "$MEMORY_DIR" 2>/dev/null || true
  fi

  if [[ -f "$DB_PATH" ]] && [[ -f "$SCRIPT_DIR/knowledge-db.sh" ]]; then
    source "$SCRIPT_DIR/knowledge-db.sh"
    RAW_RESULTS=$(kb_search "$DB_PATH" "$QUERY" 20)

    if [[ -n "$RAW_RESULTS" ]]; then
      # kb_search outputs JSON array; parse with jq so '|'/newlines in fields are safe
      RESULTS=""

      while IFS= read -r ROW; do
        local type content bead tags
        type=$(echo "$ROW" | jq -r '.type // empty' 2>/dev/null)
        [[ -z "$type" ]] && continue

        if [[ -n "$TYPE_FILTER" ]] && [[ "$type" != "$TYPE_FILTER" ]]; then
          continue
        fi

        content=$(echo "$ROW" | jq -r '.content // empty' 2>/dev/null)
        bead=$(echo "$ROW" | jq -r '.bead // empty' 2>/dev/null)
        tags=$(echo "$ROW" | jq -r '.tags_text // empty' 2>/dev/null)
        TYPE_UPPER=$(echo "$type" | tr '[:lower:]' '[:upper:]')
        RESULTS="${RESULTS}[$TYPE_UPPER] $content
  bead: $bead | $tags
"
      done < <(echo "$RAW_RESULTS" | jq -c '.[]' 2>/dev/null)

      if [[ -n "$RESULTS" ]]; then
        echo "$RESULTS"
        USED_FTS5=true
      fi
    fi
  fi
fi

if [[ "$USED_FTS5" = false ]]; then
  # Grep fallback (use -F for fixed-string matching to prevent regex metachar issues)
  RESULTS=$(grep -iF "$QUERY" "${INPUT_FILES[@]}" 2>/dev/null)

  if [[ -n "$TYPE_FILTER" ]]; then
    RESULTS=$(echo "$RESULTS" | jq --arg type "$TYPE_FILTER" 'select(.type == $type)' 2>/dev/null)
  fi

  echo "$RESULTS" | jq -rs '
    [.[] | select(.key != null)] |
    unique_by(.key) |
    sort_by(-.ts) |
    .[] |
    "[\(.type | ascii_upcase)] \(.content)\n  bead: \(.bead) | \(.tags | join(", "))"
  ' 2>/dev/null
fi
