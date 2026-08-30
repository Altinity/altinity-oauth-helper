#!/usr/bin/env bash
# integration/clickhouse/tests/cases/wirecapture-fallback-parity.sh
#
# Issue #33 phase 1, plan §18 ("wirecapture-fallback-parity.sh") and §17
# (sandbox network-isolator fallback). The wire-capture-fixture sibling of
# tests/cases/ha-fallback-parity.sh (T12b) and lib-tests.sh's own
# test_bring_up_fixture_fallback for run.sh — same technique, reshaped for
# capture-ldap-wire.sh's five services and ch-wirecap-*-net names.
#
# Sourced by tests/lib-tests.sh's cases/ auto-discovery hook, AFTER
# wirecapture-compose-parity.sh (lexical glob order: "compose-parity" <
# "fallback-parity"), so it inherits that file's compose_tmpfs_long_form
# and compose_command_list helpers in addition to everything
# ha-fallback-parity.sh's own header already documents inheriting
# (SCRIPT_DIR, RUN_TMP_DIR, pass/fail/run_and_capture, every sourced
# lib/*.sh function, and lib-tests.sh's own compose-YAML extraction
# helpers) — none of it is redefined here.
#
# Runs the REAL capture-ldap-wire.sh as a subprocess with
# WIRECAP_TEST_INVOKE_FALLBACK set (see that script's own Amendment-6
# comment) and a stub `docker` shim on PATH that records every Docker/
# Compose operation bring_up_fixture_fallback issues and answers just
# enough of `compose version/up/ps -q`, `network inspect/create/connect/
# disconnect`, and `inspect -f '{{.Name}}'` for that function to run to
# completion with no real daemon involved — the identical
# service-name-agnostic stub ha-fallback-parity.sh and lib-tests.sh's own
# fallback test already use.
#
# Asserts (plan §18):
#   - generated five-service set matches compose-wirecapture.yml exactly;
#   - per-service image/command/ports/healthcheck/volumes/env-key parity
#     for the four non-recorder services;
#   - the recorder's own image, forwarding command, healthcheck, and
#     (Amendment 2) exact tmpfs stanza all match between
#     compose-wirecapture.yml and the generated fallback;
#   - every `docker network connect` call carries `--alias`;
#   - the auth-net aliases are exactly synthetic-idp/ch-oauth-ldap/
#     ldap-helper-upstream/clickhouse-origin;
#   - the cluster-net aliases are exactly clickhouse-origin/
#     clickhouse-remote;
#   - only ch-oauth-ldap/ldap-helper-upstream/clickhouse-remote are ever
#     disconnected from the shared network (synthetic-idp and
#     clickhouse-origin keep shared membership, matching their published
#     host ports);
#   - no real Docker daemon is needed (the stub above is the only `docker`
#     on PATH for the subprocess).
#
# Diagnostics below print only compose-file field literals and Docker
# call-log lines (service/network/alias names, counts) — never a
# credential, a captured PDU, or a response body.

if [ -z "${SCRIPT_DIR:-}" ] || [ -z "${RUN_TMP_DIR:-}" ]; then
    printf 'FAIL: wirecapture-fallback-parity.sh -- expected SCRIPT_DIR/RUN_TMP_DIR to already be set by lib-tests.sh\n'
    FAILURES=$((FAILURES + 1))
    return 0 2>/dev/null || exit 1
fi
if ! command -v compose_tmpfs_long_form >/dev/null 2>&1 || ! command -v compose_command_list >/dev/null 2>&1; then
    printf 'FAIL: wirecapture-fallback-parity.sh -- expected compose_tmpfs_long_form/compose_command_list to already be defined by wirecapture-compose-parity.sh (cases/ glob ordering)\n'
    FAILURES=$((FAILURES + 1))
    return 0 2>/dev/null || exit 1
fi

# test_wirecapture_fallback_parity — mirrors ha-fallback-parity.sh's
# test_bring_up_fixture_fallback_ha, reshaped for
# compose-wirecapture.yml/capture-ldap-wire.sh's five services.
test_wirecapture_fallback_parity() {
    local prefix="capture-ldap-wire.sh bring_up_fixture_fallback"
    local stub_dir fresh_tmp call_log compose_copy out rc shared_net

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/wirecap-fallback-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Records selected Docker CLI invocations to $DOCKER_CALL_LOG and returns
# fixed, deterministic responses so bring_up_fixture_fallback
# (capture-ldap-wire.sh) can run to completion with no real Docker daemon
# involved. Service-name agnostic — the exact same stub shape as
# lib-tests.sh's own test_bring_up_fixture_fallback / ha-fallback-parity.sh
# stubs, which is why it needs no changes to carry over to this fixture's
# five services.
log_call() { printf '%s\n' "$*" >>"$DOCKER_CALL_LOG"; }

if [ "$1" = "compose" ]; then
    shift
    rest=()
    skip=0
    for a in "$@"; do
        if [ "$skip" -eq 1 ]; then
            skip=0
            continue
        fi
        case "$a" in
            -p|-f|--env-file)
                skip=1
                continue
                ;;
        esac
        rest+=("$a")
    done
    case "${rest[0]:-}" in
        version)
            exit 0
            ;;
        up)
            log_call "compose up"
            exit 0
            ;;
        ps)
            log_call "compose ps -q ${rest[2]:-}"
            printf 'cid-%s\n' "${rest[2]:-}"
            exit 0
            ;;
        *)
            log_call "compose ${rest[*]:-}"
            exit 0
            ;;
    esac
fi

if [ "$1" = "network" ]; then
    case "$2" in
        inspect)
            exit 1
            ;;
        create)
            log_call "network create net=$3"
            exit 0
            ;;
        connect)
            if [ "$3" = "--alias" ]; then
                log_call "network connect alias=$4 net=$5 cname=$6"
            else
                log_call "network connect NO-ALIAS-FLAG args=$*"
            fi
            exit 0
            ;;
        disconnect)
            log_call "network disconnect net=$3 cname=$4"
            exit 0
            ;;
        *)
            log_call "network $*"
            exit 0
            ;;
    esac
fi

if [ "$1" = "ps" ] && [ "$2" = "-a" ]; then
    # Preflight collision checks (plan §16) run before the fallback hook —
    # answer every one with no hits so this test reaches the fallback.
    exit 0
fi

if [ "$1" = "inspect" ]; then
    cid="${*: -1}"
    printf '/fake-container-%s\n' "${cid#cid-}"
    exit 0
fi

log_call "UNHANDLED: $*"
exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/wirecap-fallback-run-tmp.XXXXXX")"
    call_log="$fresh_tmp/docker-calls.log"
    compose_copy="$fresh_tmp/fallback-compose-wirecapture-copy.yml"
    : >"$call_log"
    shared_net="ch-wirecap-libtest-shared"

    out="$(PATH="$stub_dir:$PATH" \
        TMPDIR="$fresh_tmp" \
        DOCKER_NETWORK="$shared_net" \
        DOCKER_CALL_LOG="$call_log" \
        WIRECAP_TEST_INVOKE_FALLBACK=1 \
        WIRECAP_TEST_FALLBACK_COMPOSE_COPY="$compose_copy" \
        bash "$SCRIPT_DIR/capture-ldap-wire.sh" --mode generate --output "$fresh_tmp/out" 2>&1)"
    rc=$?

    if [ "$rc" -ne 0 ]; then
        fail "$prefix: hook completes daemon-free" "expected exit 0, got $rc. Output: $out"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    pass "$prefix: hook completes daemon-free"

    if [ ! -s "$compose_copy" ]; then
        fail "$prefix: generated fallback compose captured" "no non-empty file at expected copy path. Output: $out"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    pass "$prefix: generated fallback compose captured"

    # ---- service set parity (five services) ----
    local real_services fb_services
    real_services="$(extract_compose_service_names "$SCRIPT_DIR/compose-wirecapture.yml" | sort)"
    fb_services="$(extract_compose_service_names "$compose_copy" | sort)"
    if [ "$real_services" = "$fb_services" ]; then
        pass "$prefix: generated service set matches compose-wirecapture.yml"
    else
        fail "$prefix: generated service set matches compose-wirecapture.yml" "compose-wirecapture.yml=[$real_services] fallback=[$fb_services]"
    fi

    # ---- per-service config parity, the four non-recorder services ----
    local svc real_block fb_block mismatch=0 detail="" real_v fb_v
    for svc in synthetic-idp ldap-helper-upstream clickhouse-origin clickhouse-remote; do
        real_block="$(extract_compose_service_block "$SCRIPT_DIR/compose-wirecapture.yml" "$svc")"
        fb_block="$(extract_compose_service_block "$compose_copy" "$svc")"

        real_v="$(normalize_compose_image "$(compose_scalar "$real_block" image)")"
        fb_v="$(normalize_compose_image "$(compose_scalar "$fb_block" image)")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail image[$svc] "; }

        real_v="$(compose_scalar "$real_block" command)"
        fb_v="$(compose_scalar "$fb_block" command)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail command[$svc] "; }

        real_v="$(compose_sub_list "$real_block" ports | sort)"
        fb_v="$(compose_sub_list "$fb_block" ports | sort)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail ports[$svc] "; }

        real_v="$(compose_nested_scalar "$real_block" test)"
        fb_v="$(compose_nested_scalar "$fb_block" test)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail healthcheck[$svc] "; }

        real_v="$(compose_volume_dst_mode_list "$real_block")"
        fb_v="$(compose_volume_dst_mode_list "$fb_block")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail volumes[$svc] "; }

        real_v="$(compose_env_keys "$real_block")"
        fb_v="$(compose_env_keys "$fb_block")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail env-keys[$svc] "; }
    done
    if [ "$mismatch" -eq 0 ]; then
        pass "$prefix: per-service image/command/ports/healthcheck/volumes/env-keys match compose-wirecapture.yml (4 non-recorder services)"
    else
        fail "$prefix: per-service image/command/ports/healthcheck/volumes/env-keys match compose-wirecapture.yml (4 non-recorder services)" "$detail"
    fi

    # ---- recorder service: image, forwarding command, healthcheck, tmpfs ----
    local real_recorder_block fb_recorder_block rec_mismatch=0 rec_detail=""
    real_recorder_block="$(extract_compose_service_block "$SCRIPT_DIR/compose-wirecapture.yml" "ch-oauth-ldap")"
    fb_recorder_block="$(extract_compose_service_block "$compose_copy" "ch-oauth-ldap")"

    real_v="$(normalize_compose_image "$(compose_scalar "$real_recorder_block" image)")"
    fb_v="$(normalize_compose_image "$(compose_scalar "$fb_recorder_block" image)")"
    [ "$real_v" = "$fb_v" ] || { rec_mismatch=1; rec_detail="$rec_detail image "; }

    real_v="$(compose_command_list "$real_recorder_block")"
    fb_v="$(compose_command_list "$fb_recorder_block")"
    [ "$real_v" = "$fb_v" ] || { rec_mismatch=1; rec_detail="$rec_detail command "; }

    real_v="$(compose_nested_scalar "$real_recorder_block" test)"
    fb_v="$(compose_nested_scalar "$fb_recorder_block" test)"
    [ "$real_v" = "$fb_v" ] || { rec_mismatch=1; rec_detail="$rec_detail healthcheck "; }

    if [ "$rec_mismatch" -eq 0 ]; then
        pass "$prefix: recorder image/command/healthcheck match between compose-wirecapture.yml and the generated fallback"
    else
        fail "$prefix: recorder image/command/healthcheck match between compose-wirecapture.yml and the generated fallback" "$rec_detail"
    fi

    # Amendment 2: byte-identical (as a normalized "target=... mode=..."
    # string) recorder tmpfs stanza between the committed capture Compose
    # and the generated fallback.
    local real_tmpfs fb_tmpfs
    real_tmpfs="$(compose_tmpfs_long_form "$real_recorder_block")"
    fb_tmpfs="$(compose_tmpfs_long_form "$fb_recorder_block")"
    if [ "$real_tmpfs" = "$fb_tmpfs" ] && [ "$real_tmpfs" = "target=/run/ldap-wirecapture mode=0700" ]; then
        pass "$prefix: recorder tmpfs (target=/run/ldap-wirecapture mode=0700) is byte-identical between compose-wirecapture.yml and the generated fallback"
    else
        fail "$prefix: recorder tmpfs (target=/run/ldap-wirecapture mode=0700) is byte-identical between compose-wirecapture.yml and the generated fallback" "compose-wirecapture.yml='$real_tmpfs' fallback='$fb_tmpfs'"
    fi

    # ---- every network connect carries --alias (6 connects: 4 auth-net + 2 cluster-net) ----
    local connect_lines total_connects
    connect_lines="$(grep '^network connect ' "$call_log" || true)"
    total_connects="$(printf '%s\n' "$connect_lines" | grep -c . || true)"
    if [ "$total_connects" -eq 6 ] && ! printf '%s\n' "$connect_lines" | grep -q 'NO-ALIAS-FLAG'; then
        pass "$prefix: every docker network connect carries --alias (6 connects)"
    else
        fail "$prefix: every docker network connect carries --alias (6 connects)" "expected 6 connect calls all with alias=; got $total_connects: $connect_lines"
    fi

    # ---- auth-net aliases ----
    local auth_ok=1 auth_svc
    for auth_svc in synthetic-idp ch-oauth-ldap ldap-helper-upstream clickhouse-origin; do
        grep -qF "network connect alias=$auth_svc net=ch-wirecap-auth-net cname=fake-container-$auth_svc" "$call_log" || auth_ok=0
    done
    if [ "$auth_ok" -eq 1 ]; then
        pass "$prefix: auth-net aliases are synthetic-idp/ch-oauth-ldap/ldap-helper-upstream/clickhouse-origin"
    else
        fail "$prefix: auth-net aliases are synthetic-idp/ch-oauth-ldap/ldap-helper-upstream/clickhouse-origin" "call log line count: $(grep -c . "$call_log")"
    fi

    # ---- cluster-net aliases ----
    local cluster_ok=1 cluster_svc
    for cluster_svc in clickhouse-origin clickhouse-remote; do
        grep -qF "network connect alias=$cluster_svc net=ch-wirecap-cluster-net cname=fake-container-$cluster_svc" "$call_log" || cluster_ok=0
    done
    if [ "$cluster_ok" -eq 1 ]; then
        pass "$prefix: cluster-net aliases are clickhouse-origin/clickhouse-remote"
    else
        fail "$prefix: cluster-net aliases are clickhouse-origin/clickhouse-remote" "call log line count: $(grep -c . "$call_log")"
    fi

    # ---- only ch-oauth-ldap/ldap-helper-upstream/clickhouse-remote disconnected from shared ----
    local disc_ok=1 disc_svc
    for disc_svc in ch-oauth-ldap ldap-helper-upstream clickhouse-remote; do
        grep -qF "network disconnect net=$shared_net cname=fake-container-$disc_svc" "$call_log" || disc_ok=0
    done
    for disc_svc in synthetic-idp clickhouse-origin; do
        if grep -qF "network disconnect net=$shared_net cname=fake-container-$disc_svc" "$call_log"; then disc_ok=0; fi
    done
    if [ "$disc_ok" -eq 1 ]; then
        pass "$prefix: only ch-oauth-ldap/ldap-helper-upstream/clickhouse-remote are disconnected from the shared network"
    else
        fail "$prefix: only ch-oauth-ldap/ldap-helper-upstream/clickhouse-remote are disconnected from the shared network" "call log line count: $(grep -c . "$call_log")"
    fi

    rm -rf "$stub_dir" "$fresh_tmp"
}
test_wirecapture_fallback_parity
