#!/usr/bin/env bash

live_resource_file() { printf '%s/resources.jsonl\n' "${LIVE_RUN_ROOT:?}"; }

_live_resource_transition_locked() {
  local file="$1" line="$2" key="$3" state="$4" previous previous_row
  if [[ -f "$file" ]]; then
    previous="$(jq -rs --arg key "$key" '[.[]|select(.key==$key)]|last.state // ""' "$file")" || return
    previous_row="$(jq -cs --arg key "$key" '[.[]|select(.key==$key)]|last // null' "$file")" || return
    if [[ "$previous" != "" ]] && ! jq -e --argjson old "$previous_row" '
      .provider == $old.provider and .kind == $old.kind and .parent_key == $old.parent_key and
      (.at >= $old.at) and
      (if ($old.state=="PLANNED" or $old.state=="CREATING") then true else
        .canonical_id==$old.canonical_id and .digest==$old.digest and .cleanup_argv==$old.cleanup_argv and .verify_argv==$old.verify_argv end)
    ' <<<"$line" >/dev/null; then
      live_die "immutable resource ownership fields changed"; return
    fi
    case "$previous:$state" in
      :PLANNED|PLANNED:CREATING|CREATING:IDENTIFIED|IDENTIFIED:CREATED|IDENTIFIED:CLEANING|CREATED:CLEANING|CLEANING:CLEANING|CLEANING:REMOVED|REMOVED:VERIFIED|VERIFIED:VERIFIED) ;;
      *) live_die "invalid resource transition: ${previous:-NEW} -> $state"; return;;
    esac
  elif [[ "$state" != PLANNED ]]; then
    live_die "first resource transition must be PLANNED"; return
  fi
  _live_append_line "$file" "$line"
}

live_resource_transition() {
  local key="$1" kind="$2" state="$3" provider="$4" canonical_id="$5" cleanup_argv="${6:-[]}" digest="${7:-}" labels="${8:-}" verify_argv="${9:-[]}" parent_key="${10:-}"
  local intent_id=""
  [[ -n "$labels" ]] || labels='{}'
  [[ "$key" =~ ^[A-Za-z0-9._-]+$ ]] || { live_die "invalid resource key"; return; }
  case "$state" in PLANNED|CREATING|IDENTIFIED|CREATED|CLEANING|REMOVED|VERIFIED) ;; *) live_die "invalid resource state: $state";; esac
  jq -e 'type == "array" and all(.[]; type == "string")' <<<"$cleanup_argv" >/dev/null || { live_die "cleanup argv must be string array"; return; }
  jq -e 'type == "array" and all(.[]; type == "string")' <<<"$verify_argv" >/dev/null || { live_die "verify argv must be string array"; return; }
  jq -e 'type == "object"' <<<"$labels" >/dev/null || { live_die "labels must be an object"; return; }
  [[ -z "$parent_key" || ( "$parent_key" =~ ^[A-Za-z0-9._-]+$ && "$parent_key" != "$key" ) ]] || { live_die "invalid parent resource key"; return; }
  labels="$(jq -c --arg run_id "$LIVE_RUN_ID" --arg provider "$provider" '. + {"cortex.live.run_id":$run_id,"cortex.live.provider":$provider}' <<<"$labels")"
  if [[ "$state" == CREATING ]]; then
    intent_id="$canonical_id"; canonical_id=""
    [[ -n "$intent_id" && -n "$digest" ]] || { live_die "CREATING requires request intent and digest"; return; }
    [[ "$(jq length <<<"$cleanup_argv")" == 0 && "$(jq length <<<"$verify_argv")" == 0 ]] || { live_die "CREATING intent must not contain destructive cleanup or verification argv"; return; }
  elif [[ "$state" == IDENTIFIED || "$state" == CREATED ]]; then
    [[ -n "$canonical_id" && -n "$digest" ]] || { live_die "$state resource requires exact ID and digest"; return; }
    [[ "$(jq length <<<"$cleanup_argv")" -gt 0 && "$(jq length <<<"$verify_argv")" -gt 0 ]] || { live_die "$state resource requires cleanup and independent verification commands"; return; }
  fi
  local line file
  file="$(live_resource_file)"
  if [[ "$state" == PLANNED && -n "$parent_key" ]]; then
    if [[ ! -f "$file" ]] || ! jq -e --arg parent "$parent_key" 'select(.key==$parent)' "$file" >/dev/null; then
      live_die "parent resource must be registered first"; return
    fi
  fi
  line="$(jq -cn --arg run_id "$LIVE_RUN_ID" --arg key "$key" --arg kind "$kind" --arg state "$state" \
    --arg provider "$provider" --arg intent_id "$intent_id" --arg canonical_id "$canonical_id" --arg digest "$digest" --arg parent_key "$parent_key" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson cleanup_argv "$cleanup_argv" --argjson verify_argv "$verify_argv" --argjson labels "$labels" '{run_id:$run_id,key:$key,kind:$kind,state:$state,provider:$provider,intent_id:(if $intent_id=="" then null else $intent_id end),canonical_id:$canonical_id,digest:$digest,parent_key:(if $parent_key=="" then null else $parent_key end),labels:$labels,at:$at,cleanup_argv:$cleanup_argv,verify_argv:$verify_argv}')"
  local redacted_line
  redacted_line="$(printf '%s' "$line" | live_redact_stream)"
  [[ "$redacted_line" == "$line" ]] || { live_die "resource ownership fields contain registered secret material"; return; }
  live_with_lock "$file" _live_resource_transition_locked "$file" "$line" "$key" "$state" || return
  live_event resource "$line"
}

live_manifest_validate() {
  local file
  file="$(live_resource_file)"
  [[ -f "$file" && ! -L "$file" ]] || { live_die "missing or unsafe resource manifest"; return; }
  [[ "$(live_file_mode "$file")" == "600" ]] || { live_die "resource manifest must be mode 0600"; return; }
  jq -e -n --arg run_id "$LIVE_RUN_ID" '
    def transition($old;$new):
      ($old==null and $new=="PLANNED") or ($old=="PLANNED" and $new=="CREATING") or
      ($old=="CREATING" and $new=="IDENTIFIED") or
      ($old=="IDENTIFIED" and ($new=="CREATED" or $new=="CLEANING")) or
      ($old=="CREATED" and $new=="CLEANING") or ($old=="CLEANING" and ($new=="CLEANING" or $new=="REMOVED")) or
      ($old=="REMOVED" and $new=="VERIFIED") or ($old=="VERIFIED" and $new=="VERIFIED");
    reduce inputs as $row ({ok:true,resources:{}};
      .resources[$row.key] as $old |
      .ok = (.ok and
        ($row|type=="object") and ($row.run_id==$run_id) and ($row.key|type=="string" and test("^[A-Za-z0-9._-]+$")) and
        ($row.kind|type=="string" and length>0) and ($row.provider|type=="string" and length>0) and
        ($row.state|IN("PLANNED","CREATING","IDENTIFIED","CREATED","CLEANING","REMOVED","VERIFIED")) and
        ($row.at|type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
        ($row.cleanup_argv|type=="array" and all(.[];type=="string")) and ($row.verify_argv|type=="array" and all(.[];type=="string")) and
        ($row.labels|type=="object") and ($row.labels["cortex.live.run_id"]==$run_id) and ($row.labels["cortex.live.provider"]==$row.provider) and
        transition(($old.state // null);$row.state) and
        ($old==null or ($row.kind==$old.kind and $row.provider==$old.provider and $row.parent_key==$old.parent_key and $row.at >= $old.at)) and
        ($old==null or $old.state=="PLANNED" or $old.state=="CREATING" or
          ($row.canonical_id==$old.canonical_id and $row.digest==$old.digest and $row.cleanup_argv==$old.cleanup_argv and $row.verify_argv==$old.verify_argv)) and
        (if $row.state=="PLANNED" then ($row.canonical_id=="" and $row.intent_id==null and ($row.cleanup_argv|length)==0 and ($row.verify_argv|length)==0)
         elif $row.state=="CREATING" then ($row.canonical_id=="" and ($row.intent_id|type=="string" and length>0) and ($row.cleanup_argv|length)==0 and ($row.verify_argv|length)==0)
         else (($row.canonical_id|type=="string" and length>0) and ($row.digest|type=="string" and length>0) and
           ($row.cleanup_argv|index($row.canonical_id)!=null) and ($row.verify_argv|index($row.canonical_id)!=null)) end)) |
      .resources[$row.key]=$row) | .ok
  ' "$file" >/dev/null || { live_die "corrupt resource manifest semantics"; return; }
}

live_resource_latest() {
  live_manifest_validate || return
  jq -n 'reduce inputs as $row ({sequence:0,by_key:{}}; .sequence += 1 | .by_key[$row.key]=($row+{__sequence:.sequence})) | [.by_key[]] | sort_by(.__sequence)' "$(live_resource_file)"
}

live_cleanup_resources() {
  local current_provider="$1" timeout="${2:-20}" resources row provider id key kind state argv verify_json digest labels parent status=0 uncertain=0 residue=0 cleanup=() verify=()
  if [[ ! -e "$(live_resource_file)" ]]; then live_audit_write CLEAN "no resources registered"; return 0; fi
  if ! live_manifest_validate; then live_audit_write MANUAL_RECONCILIATION_REQUIRED "unsafe or corrupt manifest"; return 2; fi
  resources="$(live_resource_latest)" || return
  while IFS= read -r row; do
    provider="$(jq -r .provider <<<"$row")"; id="$(jq -r .canonical_id <<<"$row")"; key="$(jq -r .key <<<"$row")"; kind="$(jq -r .kind <<<"$row")"; state="$(jq -r .state <<<"$row")"
    if [[ "$state" == CREATING ]]; then
      live_event cleanup_refused "$(jq -cn --arg key "$key" --arg reason 'creation intent has no reconciled canonical provider identity' '{key:$key,reason:$reason}')"
      uncertain=1; status=2; continue
    fi
    [[ "$state" == IDENTIFIED || "$state" == CREATED || "$state" == CLEANING || "$state" == REMOVED ]] || continue
    if [[ -z "$id" || "$provider" != "$current_provider" ]]; then
      live_event cleanup_refused "$(jq -cn --arg key "$key" --arg reason 'provider identity mismatch or missing exact ID' '{key:$key,reason:$reason}')"
      status=2; uncertain=1; continue
    fi
    argv="$(jq -c .cleanup_argv <<<"$row")"
    verify_json="$(jq -c .verify_argv <<<"$row")"
    digest="$(jq -r .digest <<<"$row")"; labels="$(jq -c .labels <<<"$row")"; parent="$(jq -r '.parent_key // ""' <<<"$row")"
    [[ "$(jq length <<<"$argv")" -gt 0 ]] || { status=2; uncertain=1; continue; }
    [[ "$(jq length <<<"$verify_json")" -gt 0 ]] || { status=2; uncertain=1; continue; }
    jq -e --arg id "$id" 'index($id) != null' <<<"$argv" >/dev/null || { status=2; uncertain=1; continue; }
    jq -e --arg id "$id" 'index($id) != null' <<<"$verify_json" >/dev/null || { status=2; uncertain=1; continue; }
    if [[ "$state" != REMOVED ]]; then
      live_resource_transition "$key" "$kind" CLEANING "$provider" "$id" "$argv" "$digest" "$labels" "$verify_json" "$parent"
      cleanup=()
      while IFS= read -r argument; do cleanup+=("$argument"); done < <(jq -r '.[]' <<<"$argv")
    fi
    if [[ "$state" == REMOVED ]] || live_timeout_process_tree "$timeout" "${cleanup[@]}"; then
      if [[ "$state" != REMOVED ]]; then
        live_resource_transition "$key" "$kind" REMOVED "$provider" "$id" "$argv" "$digest" "$labels" "$verify_json" "$parent"
      fi
      verify=()
      while IFS= read -r argument; do verify+=("$argument"); done < <(jq -r '.[]' <<<"$verify_json")
      if live_timeout_process_tree "$timeout" "${verify[@]}"; then
        live_resource_transition "$key" "$kind" VERIFIED "$provider" "$id" "$argv" "$digest" "$labels" "$verify_json" "$parent"
      else
        status=1; residue=1
        live_event cleanup_unverified "$(jq -cn --arg key "$key" --arg id "$id" '{key:$key,canonical_id:$id}')"
      fi
    else status=1; residue=1; fi
  done < <(jq -c 'reverse[]' <<<"$resources")
  if (( uncertain )); then live_audit_write MANUAL_RECONCILIATION_REQUIRED "ownership facts were insufficient"
  elif (( residue )); then live_audit_write RESIDUE "one or more exact resources remain"
  elif (( status == 0 )); then live_audit_write CLEAN "all exact resources verified removed"
  else live_audit_write CLEANUP_UNVERIFIED "cleanup outcome could not be verified"; fi
  return "$status"
}
