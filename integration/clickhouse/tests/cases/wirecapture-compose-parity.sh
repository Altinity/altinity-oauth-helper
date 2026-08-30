#!/usr/bin/env bash
# integration/clickhouse/tests/cases/wirecapture-compose-parity.sh
#
# Issue #33 phase 1, plan §18 ("wirecapture-compose-parity.sh") and
# Amendment 2 (tmpfs extraction helper). A daemon-free, text-level parity
# check of the COMMITTED integration/clickhouse/compose-wirecapture.yml
# against integration/clickhouse/compose.yml — no `docker compose config`
# call, no daemon, no build.
#
# Sourced by tests/lib-tests.sh's cases/ auto-discovery hook — see that
# file's own header and ha-fallback-parity.sh's header — so it inherits
# SCRIPT_DIR, RUN_TMP_DIR, pass/fail/run_and_capture, every sourced
# lib/*.sh function, AND lib-tests.sh's own compose-YAML text-extraction
# helpers (extract_compose_service_names, extract_compose_service_block,
# compose_scalar, compose_nested_scalar, compose_sub_list,
# compose_volume_dst_mode_list, normalize_compose_image, compose_env_keys)
# — never redefined here.
#
# This file ALSO defines two new extraction helpers that lib-tests.sh's
# existing set cannot express, and it is sourced (by the cases/ glob's
# lexical/alphabetical order: "wirecapture-collision-preflight.sh" <
# "wirecapture-compose-parity.sh" < "wirecapture-fallback-parity.sh")
# BEFORE wirecapture-fallback-parity.sh, so that file reuses both without
# redefining them:
#
#   - compose_tmpfs_long_form BLOCK (Amendment 2): compose_sub_list and
#     compose_volume_dst_mode_list only parse short `- src:dst:mode`
#     bullet lines under a service's `volumes:` heading. The recorder's
#     private raw-evidence tmpfs (plan §14) is expressed only in the LONG
#     `volumes:` form (`- type: tmpfs` / `target: ...` / `tmpfs: {mode:
#     ...}`), which carries no colon-delimited "dst:mode" bullet at all —
#     compose_volume_dst_mode_list would silently reduce it to the
#     meaningless literal "tmpfs" for BOTH a correct and a corrupted mode,
#     never actually checking the mode. compose_tmpfs_long_form parses
#     that long-form mapping entry directly into a single comparable
#     "target=... mode=..." string.
#   - compose_command_list BLOCK (used by this file's own recorder checks
#     and reused by wirecapture-fallback-parity.sh): the recorder's
#     `command:` value is a multi-line bracketed list, not a same-line
#     scalar, so compose_scalar (which only reads content on the "    KEY:"
#     line itself) returns empty for it. compose_command_list extracts the
#     full multi-line list and normalizes any `${VAR:?message}` interpolation
#     down to `${VAR:?}` — the exact same "ignore the diagnostic MESSAGE
#     text, compare only structure" principle compose_env_keys already
#     documents for PHASE3_CLUSTER_SECRET's require-error text, since the
#     capture Compose and its generated sandbox-fallback template
#     (capture-ldap-wire.sh's bring_up_fixture_fallback) deliberately carry
#     differently-worded WIRECAP_MODE require-error messages.
#
# Diagnostics below print only compose-file field literals (image names,
# command tokens, healthcheck arrays, network/tmpfs names) — never a
# credential, a captured PDU, or a response body — so they stay leak-safe
# without any extra redaction.

if [ -z "${SCRIPT_DIR:-}" ] || [ -z "${RUN_TMP_DIR:-}" ]; then
    printf 'FAIL: wirecapture-compose-parity.sh -- expected SCRIPT_DIR/RUN_TMP_DIR to already be set by lib-tests.sh\n'
    FAILURES=$((FAILURES + 1))
    return 0 2>/dev/null || exit 1
fi

# compose_tmpfs_long_form BLOCK — see header comment above. Prints exactly
# one line, "target=<value> mode=<value>" (either half empty if the
# service's `volumes:` heading carries no `- type: tmpfs` entry at all).
compose_tmpfs_long_form() {
    printf '%s\n' "$1" | awk '
        $0 == "    volumes:" { grab = 1; next }
        grab && /^    [A-Za-z]/ { grab = 0 }
        grab && /^  [A-Za-z]/ { grab = 0 }
        grab && /^      - type: tmpfs/ { intmpfs = 1; next }
        grab && intmpfs && /^        target:/ {
            line = $0; sub(/^        target: */, "", line); target = line; next
        }
        grab && intmpfs && /^          mode:/ {
            line = $0; sub(/^          mode: */, "", line); mode = line; next
        }
        grab && intmpfs && /^      - / { intmpfs = 0 }
        END { printf "target=%s mode=%s\n", target, mode }
    '
}

# compose_multiline_field BLOCK KEY — every line strictly following a
# "    KEY:" header (4-space, header on its own line with nothing after
# the colon) up to the next 4-space or 2-space heading, each line
# left-trimmed. Returns empty when KEY is a same-line scalar instead (use
# compose_scalar for that shape).
compose_multiline_field() {
    printf '%s\n' "$1" | awk -v key="    $2:" '
        $0 == key { grab = 1; next }
        grab && /^    [A-Za-z]/ { grab = 0 }
        grab && /^  [A-Za-z]/ { grab = 0 }
        grab { line = $0; sub(/^ */, "", line); print line }
    '
}

# compose_command_list BLOCK — see header comment above.
compose_command_list() {
    compose_multiline_field "$1" command | sed -E 's/:\?[^}]*\}/:?}/g'
}

# test_wirecapture_compose_parity — the real assertions (plan §18's
# "wirecapture-compose-parity.sh" bullet list, in order).
test_wirecapture_compose_parity() {
    local prefix="compose-wirecapture.yml parity"
    local wc_file="$SCRIPT_DIR/compose-wirecapture.yml"
    local base_file="$SCRIPT_DIR/compose.yml"

    if [ ! -f "$wc_file" ]; then
        fail "$prefix: compose-wirecapture.yml exists" "not found at expected path"
        return
    fi

    # ---- exactly five services ----
    local services svc_count expected_services
    services="$(extract_compose_service_names "$wc_file" | sort)"
    svc_count="$(printf '%s\n' "$services" | grep -c . || true)"
    expected_services="$(printf '%s\n' ch-oauth-ldap clickhouse-origin clickhouse-remote ldap-helper-upstream synthetic-idp | sort)"
    if [ "$svc_count" -eq 5 ] && [ "$services" = "$expected_services" ]; then
        pass "$prefix: exactly five services (synthetic-idp, ch-oauth-ldap, ldap-helper-upstream, clickhouse-origin, clickhouse-remote)"
    else
        fail "$prefix: exactly five services (synthetic-idp, ch-oauth-ldap, ldap-helper-upstream, clickhouse-origin, clickhouse-remote)" "got $svc_count service(s): $services"
    fi

    # ---- common service parity: synthetic-idp / clickhouse-origin / clickhouse-remote ----
    local svc real_block wc_block mismatch=0 detail="" real_v wc_v
    for svc in synthetic-idp clickhouse-origin clickhouse-remote; do
        real_block="$(extract_compose_service_block "$base_file" "$svc")"
        wc_block="$(extract_compose_service_block "$wc_file" "$svc")"

        real_v="$(normalize_compose_image "$(compose_scalar "$real_block" image)")"
        wc_v="$(normalize_compose_image "$(compose_scalar "$wc_block" image)")"
        [ "$real_v" = "$wc_v" ] || { mismatch=1; detail="$detail image[$svc] "; }

        real_v="$(compose_scalar "$real_block" command)"
        wc_v="$(compose_scalar "$wc_block" command)"
        [ "$real_v" = "$wc_v" ] || { mismatch=1; detail="$detail command[$svc] "; }

        real_v="$(compose_sub_list "$real_block" ports | sort)"
        wc_v="$(compose_sub_list "$wc_block" ports | sort)"
        [ "$real_v" = "$wc_v" ] || { mismatch=1; detail="$detail ports[$svc] "; }

        real_v="$(compose_nested_scalar "$real_block" test)"
        wc_v="$(compose_nested_scalar "$wc_block" test)"
        [ "$real_v" = "$wc_v" ] || { mismatch=1; detail="$detail healthcheck[$svc] "; }

        real_v="$(compose_volume_dst_mode_list "$real_block")"
        wc_v="$(compose_volume_dst_mode_list "$wc_block")"
        [ "$real_v" = "$wc_v" ] || { mismatch=1; detail="$detail volumes[$svc] "; }

        real_v="$(compose_env_keys "$real_block")"
        wc_v="$(compose_env_keys "$wc_block")"
        [ "$real_v" = "$wc_v" ] || { mismatch=1; detail="$detail env-keys[$svc] "; }
    done
    if [ "$mismatch" -eq 0 ]; then
        pass "$prefix: synthetic-idp/clickhouse-origin/clickhouse-remote match compose.yml (image/command/ports/healthcheck/volumes/env keys)"
    else
        fail "$prefix: synthetic-idp/clickhouse-origin/clickhouse-remote match compose.yml (image/command/ports/healthcheck/volumes/env keys)" "mismatched field(s): $detail"
    fi

    # ---- upstream-helper parity: ldap-helper-upstream vs base ch-oauth-ldap ----
    local base_ldap_block wc_upstream_block up_mismatch=0 up_detail=""
    base_ldap_block="$(extract_compose_service_block "$base_file" "ch-oauth-ldap")"
    wc_upstream_block="$(extract_compose_service_block "$wc_file" "ldap-helper-upstream")"

    real_v="$(normalize_compose_image "$(compose_scalar "$base_ldap_block" image)")"
    wc_v="$(normalize_compose_image "$(compose_scalar "$wc_upstream_block" image)")"
    [ "$real_v" = "$wc_v" ] || { up_mismatch=1; up_detail="$up_detail image "; }

    real_v="$(compose_scalar "$base_ldap_block" command)"
    wc_v="$(compose_scalar "$wc_upstream_block" command)"
    [ "$real_v" = "$wc_v" ] || { up_mismatch=1; up_detail="$up_detail command "; }

    real_v="$(compose_sub_list "$base_ldap_block" ports | sort)"
    wc_v="$(compose_sub_list "$wc_upstream_block" ports | sort)"
    [ "$real_v" = "$wc_v" ] || { up_mismatch=1; up_detail="$up_detail ports "; }

    real_v="$(compose_nested_scalar "$base_ldap_block" test)"
    wc_v="$(compose_nested_scalar "$wc_upstream_block" test)"
    [ "$real_v" = "$wc_v" ] || { up_mismatch=1; up_detail="$up_detail healthcheck "; }

    real_v="$(compose_volume_dst_mode_list "$base_ldap_block")"
    wc_v="$(compose_volume_dst_mode_list "$wc_upstream_block")"
    [ "$real_v" = "$wc_v" ] || { up_mismatch=1; up_detail="$up_detail volumes "; }

    real_v="$(compose_env_keys "$base_ldap_block")"
    wc_v="$(compose_env_keys "$wc_upstream_block")"
    [ "$real_v" = "$wc_v" ] || { up_mismatch=1; up_detail="$up_detail env-keys "; }

    if [ "$up_mismatch" -eq 0 ]; then
        pass "$prefix: ldap-helper-upstream matches compose.yml's ch-oauth-ldap block (image/command/ports/healthcheck/volumes/env keys)"
    else
        fail "$prefix: ldap-helper-upstream matches compose.yml's ch-oauth-ldap block (image/command/ports/healthcheck/volumes/env keys)" "mismatched field(s): $up_detail"
    fi

    # ---- recorder (ch-oauth-ldap in compose-wirecapture.yml) ----
    local recorder_block
    recorder_block="$(extract_compose_service_block "$wc_file" "ch-oauth-ldap")"

    local recorder_image
    recorder_image="$(compose_scalar "$recorder_block" image)"
    if [ "$recorder_image" = "altinity-oauth-helper-phase3-helper:local" ]; then
        pass "$prefix: recorder service uses the shared local image altinity-oauth-helper-phase3-helper:local"
    else
        fail "$prefix: recorder service uses the shared local image altinity-oauth-helper-phase3-helper:local" "got image '$recorder_image'"
    fi

    local recorder_cmd base_cmd
    recorder_cmd="$(compose_command_list "$recorder_block")"
    base_cmd="$(compose_command_list "$base_ldap_block")"
    if [ -n "$recorder_cmd" ] && printf '%s\n' "$recorder_cmd" | command grep -qF '"/bin/ldap-wire-recorder"' \
        && printf '%s\n' "$recorder_cmd" | command grep -qF '"ldap-helper-upstream:389"'; then
        pass "$prefix: recorder command runs /bin/ldap-wire-recorder against ldap-helper-upstream:389"
    else
        fail "$prefix: recorder command runs /bin/ldap-wire-recorder against ldap-helper-upstream:389" "normalized command: $recorder_cmd"
    fi
    if [ "$recorder_cmd" != "$base_cmd" ]; then
        pass "$prefix: recorder command deliberately differs from compose.yml's ch-oauth-ldap command (it runs the recorder binary, not the real helper)"
    else
        fail "$prefix: recorder command deliberately differs from compose.yml's ch-oauth-ldap command (it runs the recorder binary, not the real helper)" "recorder command equaled the base helper command"
    fi

    # Amendment 1: readiness-file healthcheck, an explicit carve-out from
    # the base ch-oauth-ldap block's `nc -z` probe.
    local recorder_health base_ldap_health
    recorder_health="$(compose_nested_scalar "$recorder_block" test)"
    base_ldap_health="$(compose_nested_scalar "$base_ldap_block" test)"
    if [ "$recorder_health" = '["CMD", "test", "-f", "/run/ldap-wirecapture/ready"]' ]; then
        pass "$prefix: recorder healthcheck is the readiness-file probe (Amendment 1 carve-out from the base nc -z block)"
    else
        fail "$prefix: recorder healthcheck is the readiness-file probe (Amendment 1 carve-out from the base nc -z block)" "got healthcheck '$recorder_health'"
    fi
    if [ "$recorder_health" != "$base_ldap_health" ]; then
        pass "$prefix: recorder healthcheck deliberately differs from base ch-oauth-ldap's nc -z probe (N==1 invariant, plan §8.4/§21)"
    else
        fail "$prefix: recorder healthcheck deliberately differs from base ch-oauth-ldap's nc -z probe (N==1 invariant, plan §8.4/§21)" "recorder healthcheck matched the base nc -z probe verbatim"
    fi

    # Amendment 2: exact recorder tmpfs destination and mode via the new helper.
    local recorder_tmpfs
    recorder_tmpfs="$(compose_tmpfs_long_form "$recorder_block")"
    if [ "$recorder_tmpfs" = "target=/run/ldap-wirecapture mode=0700" ]; then
        pass "$prefix: recorder tmpfs is target=/run/ldap-wirecapture mode=0700 (long volumes: form)"
    else
        fail "$prefix: recorder tmpfs is target=/run/ldap-wirecapture mode=0700 (long volumes: form)" "got '$recorder_tmpfs'"
    fi

    # ---- canonical ClickHouse mounts (config.d/users.d, read-only) ----
    local ch_mounts_ok=1 ch_svc ch_real_vol ch_wc_vol
    for ch_svc in clickhouse-origin clickhouse-remote; do
        ch_real_vol="$(compose_volume_dst_mode_list "$(extract_compose_service_block "$base_file" "$ch_svc")")"
        ch_wc_vol="$(compose_volume_dst_mode_list "$(extract_compose_service_block "$wc_file" "$ch_svc")")"
        [ "$ch_real_vol" = "$ch_wc_vol" ] || ch_mounts_ok=0
    done
    if [ "$ch_mounts_ok" -eq 1 ]; then
        pass "$prefix: canonical ClickHouse config.d/users.d mounts match compose.yml on both nodes"
    else
        fail "$prefix: canonical ClickHouse config.d/users.d mounts match compose.yml on both nodes" "volume dst:mode list(s) differ from compose.yml"
    fi

    # ---- exact, distinct network names ----
    local auth_net_name cluster_net_name
    auth_net_name="$(command grep -A1 '^  auth-net:' "$wc_file" | command grep 'name:' | sed 's/^ *name: *//')"
    cluster_net_name="$(command grep -A1 '^  cluster-net:' "$wc_file" | command grep 'name:' | sed 's/^ *name: *//')"
    if [ "$auth_net_name" = "ch-wirecap-auth-net" ] && [ "$cluster_net_name" = "ch-wirecap-cluster-net" ]; then
        pass "$prefix: network names are exactly ch-wirecap-auth-net/ch-wirecap-cluster-net"
    else
        fail "$prefix: network names are exactly ch-wirecap-auth-net/ch-wirecap-cluster-net" "auth-net='$auth_net_name' cluster-net='$cluster_net_name'"
    fi
}
test_wirecapture_compose_parity
