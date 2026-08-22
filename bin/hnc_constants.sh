#!/system/bin/sh
# HNC shared constants. Keep duplicated shell values in one place.
# v5.3.0-rc9: introduced for MARK_BASE and local/remote ports.

# Base directory — accept HNC_DIR or HNC, default to /data/local/hnc.
# Scripts sourcing this file get a consistent base regardless of which
# variable name they use internally.
HNC_DIR="${HNC_DIR:-${HNC:-/data/local/hnc}}"
# shellcheck disable=SC2034
HNC="$HNC_DIR"

# fwmark base offset for HNC per-device traffic shaping marks.
HNC_MARK_BASE=0x800000

# HTTP ports used by hnc_httpd/watchdog.
HNC_HTTPS_PORT=8443
HNC_LOOPBACK_PORT=8444
HNC_HTTP_REDIR_PORT=8080
