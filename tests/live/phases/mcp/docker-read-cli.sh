#!/bin/sh
# Deterministic read-only Docker CLI boundary for compose_doctor.  It implements
# only the two read commands used by the diagnostic and rejects every mutation.
case "${1:-}" in
  inspect)
    printf '%s\n' '{"Id":"mcp-live-candidate","Name":"/'"${CORTEX_COMPOSE_CONTAINER:-cortex-live-candidate}"'","Image":"sha256:mcp-live","State":{"Status":"running","Health":{"Status":"healthy"}},"Config":{"Image":"cortex-live-candidate","Labels":{"com.docker.compose.project":"'"${CORTEX_COMPOSE_PROJECT:-cortex-live}"'","com.docker.compose.service":"candidate","com.docker.compose.project.working_dir":"/run/cortex-live","com.docker.compose.project.config_files":"/run/cortex-live/compose.yaml"}},"HostConfig":{"NetworkMode":"cortex-live_isolated"},"Mounts":[{"Type":"volume","Name":"cortex-data","Source":"/run/cortex-live/state","Destination":"/data"}],"NetworkSettings":{"Ports":{"3100/tcp":[{"HostIp":"127.0.0.1","HostPort":"3100"}],"1514/udp":[{"HostIp":"127.0.0.1","HostPort":"1514"}],"1514/tcp":[{"HostIp":"127.0.0.1","HostPort":"1514"}]}}}'
    ;;
  ps)
    # Label lookups return the configured candidate; published-port ownership
    # returns its run-owned synthetic ID.
    case "$*" in
      *com.docker.compose.service*) printf '%s\n' "${CORTEX_COMPOSE_CONTAINER:-cortex-live-candidate}" ;;
      *publish=*) printf '%s\t%s\n' mcp-live-candidate "${CORTEX_COMPOSE_CONTAINER:-cortex-live-candidate}" ;;
      *) exit 0 ;;
    esac
    ;;
  version) printf '%s\n' '29.1.3-live-read-boundary' ;;
  *) printf '%s\n' 'read-only docker fixture: operation denied' >&2; exit 64 ;;
esac
