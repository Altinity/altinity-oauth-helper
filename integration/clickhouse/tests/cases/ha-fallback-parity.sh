#!/usr/bin/env bash
# integration/clickhouse/tests/cases/ha-fallback-parity.sh
#
# T12b (issue #19 phase 5, plan §17.3/§17.5): a daemon-free shim test of
# run-ha.sh's bring_up_fixture_fallback — the HA-shaped sibling of
# lib-tests.sh's own test_bring_up_fixture_fallback for run.sh, generalized
# the same way that function already is (its stub `docker` is service-name
# agnostic, so the same technique carries over unchanged for six services
# instead of four).
#
# Sourced by tests/lib-tests.sh's cases/ auto-discovery hook — see that
# file's own header — so it inherits SCRIPT_DIR, RUN_TMP_DIR, pass/fail/
# run_and_capture, every sourced lib/*.sh function, AND lib-tests.sh's own
# compose-YAML text-extraction helpers (extract_compose_service_names,
# extract_compose_service_block, compose_scalar, compose_nested_scalar,
# compose_sub_list, compose_volume_dst_mode_list, normalize_compose_image,
# compose_env_keys) — never redefined here.
#
# Runs the REAL run-ha.sh as a subprocess with PHASE5_HA_TEST_INVOKE_FALLBACK
# set (see that script's own comment on the hook) and a stub `docker` shim
# on PATH that records every Docker/Compose operation
# bring_up_fixture_fallback issues and answers just enough of `compose
# version/up/ps -q`, `network inspect/create/connect/disconnect`, and
# `inspect -f '{{.Name}}'` for that function to run to completion with no
# real daemon involved — the identical technique lib-tests.sh's own
# test_bring_up_fixture_fallback uses, generalized to six services.
#
# Asserts (plan §17.5's "service-for-service parity, not only image-digest
# parity"):
#   - generated service set matches compose-ha.yml exactly (six services);
#   - per-service image/command/ports/healthcheck/volumes/env-keys parity
#     for the five non-HAProxy services;
#   - the HAProxy service's own image digest, config-mount volume, and
#     healthcheck all match between compose-ha.yml and the generated
#     fallback — and that digest equals run-ha.sh's own
#     HAPROXY_DIGEST_IMAGE constant (proving normal/fallback/constant three-
#     way agreement, not just normal/fallback);
#   - every `docker network connect` call carries `--alias`;
#   - the auth-net aliases are exactly synthetic-idp/ch-oauth-ldap-a/
#     ch-oauth-ldap-b/ch-oauth-ldap/clickhouse-origin;
#   - the cluster-net aliases are exactly clickhouse-origin/
#     clickhouse-remote;
#   - only ch-oauth-ldap-a/ch-oauth-ldap-b/ch-oauth-ldap/clickhouse-remote
#     are ever disconnected from the shared network (synthetic-idp and
#     clickhouse-origin keep shared membership, matching their published
#     host ports).

if [ -z "${SCRIPT_DIR:-}" ] || [ -z "${RUN_TMP_DIR:-}" ]; then
    printf 'FAIL: ha-fallback-parity.sh -- expected SCRIPT_DIR/RUN_TMP_DIR to already be set by lib-tests.sh\n'
    FAILURES=$((FAILURES + 1))
    return 0 2>/dev/null || exit 1
fi

# test_bring_up_fixture_fallback_ha — mirrors lib-tests.sh's
# test_bring_up_fixture_fallback for compose.yml/run.sh, reshaped for
# compose-ha.yml/run-ha.sh's six services and HAProxy frontend.
test_bring_up_fixture_fallback_ha() {
    local prefix="run-ha.sh bring_up_fixture_fallback"
    local stub_dir fresh_tmp call_log compose_copy out rc shared_net

    stub_dir="$(mktemp -d "$RUN_TMP_DIR/ha-fallback-stub-bin.XXXXXX")"
    cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Records selected Docker CLI invocations to $DOCKER_CALL_LOG and returns
# fixed, deterministic responses so bring_up_fixture_fallback (run-ha.sh)
# can run to completion with no real Docker daemon involved. Service-name
# agnostic — the exact same stub shape as lib-tests.sh's own
# test_bring_up_fixture_fallback stub, which is why it needs no changes to
# carry over to six services instead of four.
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

if [ "$1" = "inspect" ]; then
    cid="${*: -1}"
    printf '/fake-container-%s\n' "${cid#cid-}"
    exit 0
fi

log_call "UNHANDLED: $*"
exit 0
STUB
    chmod +x "$stub_dir/docker"

    fresh_tmp="$(mktemp -d "$RUN_TMP_DIR/ha-fallback-run-tmp.XXXXXX")"
    call_log="$fresh_tmp/docker-calls.log"
    compose_copy="$fresh_tmp/fallback-compose-ha-copy.yml"
    : >"$call_log"
    shared_net="ch-phase5-ha-libtest-shared"

    out="$(PATH="$stub_dir:$PATH" \
        TMPDIR="$fresh_tmp" \
        DOCKER_NETWORK="$shared_net" \
        DOCKER_CALL_LOG="$call_log" \
        PHASE5_HA_TEST_INVOKE_FALLBACK=1 \
        PHASE5_HA_TEST_FALLBACK_COMPOSE_COPY="$compose_copy" \
        bash "$SCRIPT_DIR/run-ha.sh" 2>&1)"
    rc=$?

    if [ "$rc" -ne 0 ]; then
        fail "$prefix: hook completes daemon-free" "expected exit 0, got $rc. Output: $out"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    pass "$prefix: hook completes daemon-free"

    if [ ! -s "$compose_copy" ]; then
        fail "$prefix: generated fallback compose captured" "no non-empty file at $compose_copy. Output: $out"
        rm -rf "$stub_dir" "$fresh_tmp"
        return
    fi
    pass "$prefix: generated fallback compose captured"

    # ---- service set parity (six services) ----
    local real_services fb_services
    real_services="$(extract_compose_service_names "$SCRIPT_DIR/compose-ha.yml" | sort)"
    fb_services="$(extract_compose_service_names "$compose_copy" | sort)"
    if [ "$real_services" = "$fb_services" ]; then
        pass "$prefix: generated service set matches compose-ha.yml"
    else
        fail "$prefix: generated service set matches compose-ha.yml" "compose-ha.yml=[$real_services] fallback=[$fb_services]"
    fi

    # ---- per-service config parity, the five non-HAProxy services ----
    local svc real_block fb_block mismatch=0 detail="" real_v fb_v
    for svc in synthetic-idp ch-oauth-ldap-a ch-oauth-ldap-b clickhouse-origin clickhouse-remote; do
        real_block="$(extract_compose_service_block "$SCRIPT_DIR/compose-ha.yml" "$svc")"
        fb_block="$(extract_compose_service_block "$compose_copy" "$svc")"

        real_v="$(normalize_compose_image "$(compose_scalar "$real_block" image)")"
        fb_v="$(normalize_compose_image "$(compose_scalar "$fb_block" image)")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail image[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_scalar "$real_block" command)"
        fb_v="$(compose_scalar "$fb_block" command)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail command[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_sub_list "$real_block" ports | sort)"
        fb_v="$(compose_sub_list "$fb_block" ports | sort)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail ports[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_nested_scalar "$real_block" test)"
        fb_v="$(compose_nested_scalar "$fb_block" test)"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail healthcheck[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_volume_dst_mode_list "$real_block")"
        fb_v="$(compose_volume_dst_mode_list "$fb_block")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail volumes[$svc]:'$real_v'!='$fb_v' "; }

        real_v="$(compose_env_keys "$real_block")"
        fb_v="$(compose_env_keys "$fb_block")"
        [ "$real_v" = "$fb_v" ] || { mismatch=1; detail="$detail env-keys[$svc]:'$real_v'!='$fb_v' "; }
    done
    if [ "$mismatch" -eq 0 ]; then
        pass "$prefix: per-service image/command/ports/healthcheck/volumes/env-keys match compose-ha.yml (5 non-HAProxy services)"
    else
        fail "$prefix: per-service image/command/ports/healthcheck/volumes/env-keys match compose-ha.yml (5 non-HAProxy services)" "$detail"
    fi

    # ---- HAProxy service: digest + config mount + healthcheck parity ----
    local real_haproxy_block fb_haproxy_block real_digest fb_digest hp_detail="" hp_mismatch=0
    real_haproxy_block="$(extract_compose_service_block "$SCRIPT_DIR/compose-ha.yml" ch-oauth-ldap)"
    fb_haproxy_block="$(extract_compose_service_block "$compose_copy" ch-oauth-ldap)"

    real_digest="$(printf '%s\n' "$real_haproxy_block" | command grep -oE 'haproxy@sha256:[0-9a-f]+' | head -n1)"
    fb_digest="$(printf '%s\n' "$fb_haproxy_block" | command grep -oE 'haproxy@sha256:[0-9a-f]+' | head -n1)"
    if [ -n "$real_digest" ] && [ "$real_digest" = "$fb_digest" ]; then
        pass "$prefix: HAProxy image digest matches between compose-ha.yml and the generated fallback"
    else
        fail "$prefix: HAProxy image digest matches between compose-ha.yml and the generated fallback" "compose-ha.yml='$real_digest' fallback='$fb_digest'"
    fi

    # Cross-check against run-ha.sh's OWN HAPROXY_DIGEST_IMAGE constant
    # (the single source both definitions are supposed to read from) —
    # extracted straight from the script's source text, not re-derived, so
    # this genuinely proves three-way agreement rather than only comparing
    # the two YAML files against each other.
    local script_const
    script_const="$(command grep -oE 'HAPROXY_DIGEST_IMAGE="haproxy@sha256:[0-9a-f]+"' "$SCRIPT_DIR/run-ha.sh" | head -n1 | command grep -oE 'haproxy@sha256:[0-9a-f]+')"
    if [ -n "$script_const" ] && [ "$script_const" = "$real_digest" ]; then
        pass "$prefix: HAProxy digest matches run-ha.sh's own HAPROXY_DIGEST_IMAGE constant"
    else
        fail "$prefix: HAProxy digest matches run-ha.sh's own HAPROXY_DIGEST_IMAGE constant" "run-ha.sh constant='$script_const' compose-ha.yml='$real_digest'"
    fi

    real_v="$(compose_volume_dst_mode_list "$real_haproxy_block")"
    fb_v="$(compose_volume_dst_mode_list "$fb_haproxy_block")"
    [ "$real_v" = "$fb_v" ] || { hp_mismatch=1; hp_detail="$hp_detail volumes:'$real_v'!='$fb_v' "; }

    real_v="$(compose_nested_scalar "$real_haproxy_block" test)"
    fb_v="$(compose_nested_scalar "$fb_haproxy_block" test)"
    [ "$real_v" = "$fb_v" ] || { hp_mismatch=1; hp_detail="$hp_detail healthcheck:'$real_v'!='$fb_v' "; }

    if [ "$hp_mismatch" -eq 0 ]; then
        pass "$prefix: HAProxy config-mount volume and healthcheck match between compose-ha.yml and the generated fallback"
    else
        fail "$prefix: HAProxy config-mount volume and healthcheck match between compose-ha.yml and the generated fallback" "$hp_detail"
    fi

    # ---- every network connect carries --alias (7 connects: 5 auth-net + 2 cluster-net) ----
    local connect_lines total_connects
    connect_lines="$(grep '^network connect ' "$call_log" || true)"
    total_connects="$(printf '%s\n' "$connect_lines" | grep -c . || true)"
    if [ "$total_connects" -eq 7 ] && ! printf '%s\n' "$connect_lines" | grep -q 'NO-ALIAS-FLAG'; then
        pass "$prefix: every docker network connect carries --alias (7 connects)"
    else
        fail "$prefix: every docker network connect carries --alias (7 connects)" "expected 7 connect calls all with alias=; got: $connect_lines"
    fi

    # ---- auth-net aliases ----
    local auth_ok=1 auth_svc
    for auth_svc in synthetic-idp ch-oauth-ldap-a ch-oauth-ldap-b ch-oauth-ldap clickhouse-origin; do
        grep -qF "network connect alias=$auth_svc net=ch-phase5-ha-auth-net cname=fake-container-$auth_svc" "$call_log" || auth_ok=0
    done
    if [ "$auth_ok" -eq 1 ]; then
        pass "$prefix: auth-net aliases are synthetic-idp/ch-oauth-ldap-a/ch-oauth-ldap-b/ch-oauth-ldap/clickhouse-origin"
    else
        fail "$prefix: auth-net aliases are synthetic-idp/ch-oauth-ldap-a/ch-oauth-ldap-b/ch-oauth-ldap/clickhouse-origin" "call log: $(cat "$call_log")"
    fi

    # ---- cluster-net aliases ----
    local cluster_ok=1 cluster_svc
    for cluster_svc in clickhouse-origin clickhouse-remote; do
        grep -qF "network connect alias=$cluster_svc net=ch-phase5-ha-cluster-net cname=fake-container-$cluster_svc" "$call_log" || cluster_ok=0
    done
    if [ "$cluster_ok" -eq 1 ]; then
        pass "$prefix: cluster-net aliases are clickhouse-origin/clickhouse-remote"
    else
        fail "$prefix: cluster-net aliases are clickhouse-origin/clickhouse-remote" "call log: $(cat "$call_log")"
    fi

    # ---- only helper A/B + HAProxy + remote disconnected from shared ----
    local disc_ok=1 disc_svc
    for disc_svc in ch-oauth-ldap-a ch-oauth-ldap-b ch-oauth-ldap clickhouse-remote; do
        grep -qF "network disconnect net=$shared_net cname=fake-container-$disc_svc" "$call_log" || disc_ok=0
    done
    for disc_svc in synthetic-idp clickhouse-origin; do
        if grep -qF "network disconnect net=$shared_net cname=fake-container-$disc_svc" "$call_log"; then disc_ok=0; fi
    done
    if [ "$disc_ok" -eq 1 ]; then
        pass "$prefix: only ch-oauth-ldap-a/ch-oauth-ldap-b/ch-oauth-ldap/clickhouse-remote are disconnected from the shared network"
    else
        fail "$prefix: only ch-oauth-ldap-a/ch-oauth-ldap-b/ch-oauth-ldap/clickhouse-remote are disconnected from the shared network" "call log: $(cat "$call_log")"
    fi

    rm -rf "$stub_dir" "$fresh_tmp"
}
test_bring_up_fixture_fallback_ha
