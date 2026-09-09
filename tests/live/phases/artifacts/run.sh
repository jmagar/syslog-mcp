#!/usr/bin/env bash
set -euo pipefail

artifact_native_platform() {
  case "$(uname -s)-$(uname -m)" in Linux-x86_64) echo linux-amd64;; Linux-aarch64|Linux-arm64) echo linux-arm64;; Darwin-arm64) echo darwin-arm64;; *) echo unknown;; esac
}

artifact_validate_manifest_schema() {
  python3 - "$LIVE_PROJECT_ROOT/tests/live/contracts/releases/artifact-manifest.schema.json" "$1" <<'PY'
import json, pathlib, re, sys, urllib.parse
schema = json.loads(pathlib.Path(sys.argv[1]).read_text())
manifest = json.loads(pathlib.Path(sys.argv[2]).read_text())
top_keys = set(schema["properties"])
if not isinstance(manifest, dict) or set(manifest) - top_keys or any(k not in manifest for k in schema["required"]):
    raise SystemExit("artifact manifest schema violation: invalid top-level properties")
if manifest["schema"] != schema["properties"]["schema"]["const"]:
    raise SystemExit("artifact manifest schema violation: schema identifier")
if not re.fullmatch(schema["properties"]["release"]["pattern"], manifest["release"]):
    raise SystemExit("artifact manifest schema violation: release")
artifacts = manifest["artifacts"]
item_schema = schema["properties"]["artifacts"]["items"]
if not isinstance(artifacts, list) or len(artifacts) < schema["properties"]["artifacts"]["minItems"]:
    raise SystemExit("artifact manifest schema violation: artifacts")
for index, artifact in enumerate(artifacts):
    if not isinstance(artifact, dict) or set(artifact) - set(item_schema["properties"]) or any(k not in artifact for k in item_schema["required"]):
        raise SystemExit(f"artifact manifest schema violation: artifact {index} properties")
    for key in ("name", "origin", "path", "sha256"):
        if not isinstance(artifact[key], str) or any(ord(c) < 32 for c in artifact[key]):
            raise SystemExit(f"artifact manifest schema violation: artifact {index} {key}")
    if not re.fullmatch(item_schema["properties"]["name"]["pattern"], artifact["name"]):
        raise SystemExit(f"artifact manifest schema violation: artifact {index} name")
    if artifact["kind"] not in item_schema["properties"]["kind"]["enum"] or artifact["platform"] not in item_schema["properties"]["platform"]["enum"]:
        raise SystemExit(f"artifact manifest schema violation: artifact {index} enum")
    if not re.match(item_schema["properties"]["origin"]["pattern"], artifact["origin"]) or not re.fullmatch(item_schema["properties"]["sha256"]["pattern"], artifact["sha256"]):
        raise SystemExit(f"artifact manifest schema violation: artifact {index} origin or digest")
    signature = artifact.get("signature")
    if artifact["origin"].startswith("https://"):
        required = {"type", "identity", "issuer", "bundle"}
        if not isinstance(signature, dict) or set(signature) != required or signature["type"] not in ("cosign-blob", "cosign-image"):
            raise SystemExit(f"artifact manifest schema violation: artifact {index} remote signature")
        if not all(isinstance(signature[k], str) and signature[k] for k in required) or not urllib.parse.urlparse(signature["issuer"]).scheme:
            raise SystemExit(f"artifact manifest schema violation: artifact {index} remote signature values")
    elif signature is not None:
        raise SystemExit(f"artifact manifest schema violation: artifact {index} local signature")
PY
}

artifact_canonical_file() {
  python3 - "$1" <<'PY'
import os, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.is_symlink() or not path.is_file():
    raise SystemExit("artifact must be an existing regular non-symlink file")
print(os.path.realpath(path))
PY
}

artifact_assert_trusted_remote_identity() {
  local row="$1" release="$2" kind="$3" path="$4" origin="$5" expected="$6"
  local signature_type identity issuer expected_identity basename
  signature_type="$(jq -r '.signature.type' <<<"$row")"
  identity="$(jq -r '.signature.identity' <<<"$row")"
  issuer="$(jq -r '.signature.issuer' <<<"$row")"
  expected_identity="https://github.com/dinglebear-ai/cortex/.github/workflows/release.yml@refs/tags/v$release"
  [[ "$issuer" == "https://token.actions.githubusercontent.com" ]] || { live_die "untrusted artifact certificate issuer"; return; }
  [[ "$identity" == "$expected_identity" ]] || { live_die "untrusted artifact workflow identity"; return; }
  case "$kind:$signature_type" in
    container:cosign-image)
      [[ "$path" == "ghcr.io/dinglebear-ai/cortex@sha256:$expected" ]] || { live_die "container reference digest does not match manifest digest"; return; }
      [[ "$origin" == "https://ghcr.io/v2/dinglebear-ai/cortex/manifests/sha256:$expected" ]] || { live_die "container origin is not bound to manifest digest"; return; }
      ;;
    container:*) live_die "container requires cosign-image provenance"; return ;;
    *:cosign-blob)
      basename="$(basename "$path")"
      [[ "$origin" == "https://github.com/dinglebear-ai/cortex/releases/download/v$release/$basename" ]] || { live_die "release origin is not bound to tag and artifact filename"; return; }
      ;;
    *) live_die "release file requires cosign-blob provenance"; return ;;
  esac
}

artifact_verify_remote_provenance() {
  local row="$1" release="$2" kind="$3" path="$4" origin="$5" expected="$6" signature signature_type bundle identity issuer canonical_bundle
  signature="$(jq -c .signature <<<"$row")"
  signature_type="$(jq -r .type <<<"$signature")"; bundle="$(jq -r .bundle <<<"$signature")"
  identity="$(jq -r .identity <<<"$signature")"; issuer="$(jq -r .issuer <<<"$signature")"
  command -v cosign >/dev/null || live_die "cosign is required for remote artifact provenance"
  artifact_assert_trusted_remote_identity "$row" "$release" "$kind" "$path" "$origin" "$expected"
  canonical_bundle="$(artifact_canonical_file "$bundle")" || live_die "invalid provenance bundle"
  case "$signature_type:$kind" in
    cosign-image:container)
      cosign verify --offline --bundle "$canonical_bundle" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$path" >/dev/null || live_die "container provenance verification failed";;
    cosign-blob:*)
      cosign verify-blob --offline --bundle "$canonical_bundle" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$path" >/dev/null || live_die "artifact provenance verification failed";;
    *) live_die "signature type does not match artifact kind";;
  esac
}

artifact_qualify_native_archive() {
  local extracted="$1" platform="$2" release="$3" evidence_dir="$4" name="$5"
  local executable version_output help_output expected_name
  case "$platform" in
    linux-amd64|linux-arm64|darwin-arm64) expected_name=cortex ;;
    windows-amd64) expected_name=cortex.exe ;;
    *) live_die "native archive has unsupported platform: $platform"; return ;;
  esac
  executable="$extracted/$expected_name"
  [[ -f "$executable" && ! -L "$executable" ]] || { live_die "native archive lacks root $expected_name executable: $name"; return; }
  [[ -x "$executable" ]] || { live_die "native archive cortex binary is not executable: $name"; return; }
  # The release archives intentionally contain one root executable. Rejecting
  # extra payload prevents an archive from qualifying an unrelated runnable
  # cortex binary while also shipping unexpected files.
  [[ "$(find -P "$extracted" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" == 1 ]] || {
    live_die "native archive must contain exactly one root executable: $name"; return;
  }
  version_output="$evidence_dir/$name.version.txt"
  help_output="$evidence_dir/$name.help.txt"
  live_timeout 10 live_sanitized_env "$executable" --version >"$version_output" || {
    live_die "packaged cortex --version failed or timed out: $name"; return;
  }
  [[ "$(head -1 "$version_output")" == "cortex $release" ]] || {
    live_die "packaged cortex version does not match release $release: $name"; return;
  }
  live_timeout 10 live_sanitized_env "$executable" --help >"$help_output" || {
    live_die "packaged cortex --help smoke failed or timed out: $name"; return;
  }
  grep -q 'Usage:' "$help_output" || { live_die "packaged cortex help smoke lacked usage output: $name"; return; }
}

artifact_qualify_manifest() {
  local manifest="$1" dir="$LIVE_RUN_ROOT/artifacts/releases" native release row name kind path expected actual platform out version image_platform install_root origin canonical_path
  mkdir -p "$dir" "$LIVE_RUN_ROOT/artifact-sandbox/home" "$LIVE_RUN_ROOT/artifact-sandbox/tmp"
  [[ -f "$manifest" && ! -L "$manifest" ]] || live_die "artifact manifest missing or unsafe"
  artifact_validate_manifest_schema "$manifest"
  native="$(artifact_native_platform)"; release="$(jq -r .release "$manifest")"; : >"$dir/ledger.jsonl"
  while IFS= read -r row; do
    name="$(jq -r .name <<<"$row")"; kind="$(jq -r .kind <<<"$row")"; path="$(jq -r .path <<<"$row")"; expected="$(jq -r .sha256 <<<"$row")"; platform="$(jq -r .platform <<<"$row")"; origin="$(jq -r .origin <<<"$row")"
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || live_die "unsafe artifact name"
    if [[ "$kind" == container ]]; then
      [[ "$origin" == https://* ]] || live_die "container artifacts require an attested remote origin"
      artifact_verify_remote_provenance "$row" "$release" "$kind" "$path" "$origin" "$expected"
      docker image inspect "$path" --format '{{json .RepoDigests}}' | jq -e --arg ref "$path" 'index($ref)!=null' >/dev/null || live_die "local container is not the attested registry digest: $name"
      actual="$expected"
      image_platform="$(docker image inspect "$path" --format '{{.Os}}-{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
      [[ "$platform" == any || "$platform" == "$image_platform" ]] || live_die "container platform mismatch: $name"
      out="$dir/$name.version.txt"
      env -i PATH="$PATH" HOME="$LIVE_RUN_ROOT/artifact-sandbox/home" docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 512m --cpus 1 -e HOME=/nonexistent "$path" cortex --version >"$out"
      version="$(head -1 "$out")"; [[ "$version" == *"$release"* ]] || live_die "container version mismatch: $name"
    else
      canonical_path="$(artifact_canonical_file "$path")" || live_die "unsafe or missing artifact: $name"
      path="$canonical_path"
      if [[ "$origin" == file://* ]]; then
        [[ "$origin" == "file://$canonical_path" ]] || live_die "local artifact origin does not match its canonical path: $name"
      else
        artifact_verify_remote_provenance "$row" "$release" "$kind" "$path" "$origin" "$expected"
      fi
      actual="$(live_sha256 "$path")"; [[ "$actual" == "$expected" ]] || live_die "artifact digest mismatch: $name"
      case "$kind" in
        binary|generated-cli)
          [[ -x "$path" ]] || live_die "artifact is not executable: $name"
          if [[ "$platform" == "$native" || "$platform" == any ]]; then
            out="$dir/$name.version.txt"; live_sanitized_env "$path" --version >"$out"; version="$(head -1 "$out")"
          else version="structural-only:$platform"; fi;;
        archive|plugin|mcpb)
          out="$LIVE_RUN_ROOT/artifact-sandbox/extract-$name"; mkdir -p "$out"
          python3 "$LIVE_PROJECT_ROOT/tests/live/phases/artifacts/safe_extract.py" "$path" "$out" --max-files 2000 --max-bytes 268435456 >"$dir/$name.extract.txt"
          if [[ "$kind" == archive && "$platform" == "$native" ]]; then
            artifact_qualify_native_archive "$out" "$platform" "$release" "$dir" "$name"
          fi
          if [[ "$kind" == plugin ]]; then find "$out" -path '*/skills/*/SKILL.md' -print -quit | grep -q . || live_die "plugin lacks skills: $name"; fi
          if [[ "$kind" == mcpb ]]; then
            mcpb_manifest="$(find "$out" -name manifest.json -print -quit)"; [[ -n "$mcpb_manifest" ]] || live_die "MCPB lacks manifest: $name"
            jq -e --arg release "$release" '.version==$release and .server.type=="binary" and (.server.entry_point|type=="string")' "$mcpb_manifest" >/dev/null || live_die "MCPB manifest/version mismatch: $name"
          fi
          if [[ "$kind" == plugin || "$kind" == mcpb ]]; then
            install_root="$LIVE_RUN_ROOT/artifact-sandbox/installed-$name"
            [[ "$install_root" == "$LIVE_RUN_ROOT"/* ]] || live_die "install root escaped run"
            cp -R "$out" "$install_root"; [[ -d "$install_root" ]] || live_die "install failed: $name"
            rm -rf "$install_root"; [[ ! -e "$install_root" ]] || live_die "uninstall failed: $name"
          fi
          version="artifact-qualified:$platform";;
        *) live_die "unknown artifact kind: $kind";;
      esac
    fi
    jq -cn --arg name "$name" --arg kind "$kind" --arg expected "$expected" --arg observed "$actual" --arg platform "$platform" --arg result "$version" '{name:$name,kind:$kind,expected_sha256:$expected,observed_sha256:$observed,platform:$platform,result:$result,network:"none",home:"run-owned",credentials_inherited:false,docker_socket_mounted:false}' >>"$dir/ledger.jsonl"
  done < <(jq -c '.artifacts[]' "$manifest")
  jq -e -s 'length>0 and all(.[];.expected_sha256==.observed_sha256 and .credentials_inherited==false and .docker_socket_mounted==false)' "$dir/ledger.jsonl" >/dev/null
  live_terminal_disposition artifacts pass artifacts/releases/ledger.jsonl
}
