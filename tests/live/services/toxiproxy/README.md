# Toxiproxy dependency

The isolated profile uses the upstream `ghcr.io/shopify/toxiproxy` image pinned by
digest through `LIVE_TOXIPROXY_IMAGE`. The API is published on a provider-assigned
loopback port. Test scenarios create only run-prefixed proxies and delete them in
teardown; the service has no host socket, capabilities, writable root, or external
network.
