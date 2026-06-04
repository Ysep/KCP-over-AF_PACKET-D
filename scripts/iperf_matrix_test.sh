#!/usr/bin/env bash
#
# Run the iperf3 performance matrix used during the 2026-06-04 tunnel tuning.
#
# Default topology:
#   A/client  192.168.1.148 -> B/frontend 192.168.1.198:5201
#   B/C tunnel over AF_PACKET
#   C/backend 192.168.1.199 -> D/server 192.168.1.149:5201
#
# Override defaults with environment variables, for example:
#   CLIENT_HOST=192.168.1.148 FRONTEND_HOST=192.168.1.198 \
#   BACKEND_HOST=192.168.1.199 SERVER_HOST=192.168.1.149 \
#   ./scripts/iperf_matrix_test.sh
#
# Optional:
#   APPLY_SYSCTL=1 ./scripts/iperf_matrix_test.sh
#   CASE_FILTER=base4096 ./scripts/iperf_matrix_test.sh

set -euo pipefail

CLIENT_HOST="${CLIENT_HOST:-192.168.1.148}"
FRONTEND_HOST="${FRONTEND_HOST:-192.168.1.198}"
BACKEND_HOST="${BACKEND_HOST:-192.168.1.199}"
SERVER_HOST="${SERVER_HOST:-192.168.1.149}"

SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:--F /dev/null -o BatchMode=yes -o ConnectTimeout=8}"

KCP_DIR="${KCP_DIR:-/root/kcp}"
FRONTEND_CONFIG="${FRONTEND_CONFIG:-iperf-node-b.json}"
BACKEND_CONFIG="${BACKEND_CONFIG:-iperf-node-c.json}"
KCP_BIN="${KCP_BIN:-./kcp-afpacket}"

SERVER_PORT="${SERVER_PORT:-5201}"
TEST_SECONDS="${TEST_SECONDS:-10}"
PARALLEL="${PARALLEL:-1}"
CASE_FILTER="${CASE_FILTER:-}"
RESULT_DIR="${RESULT_DIR:-/tmp/kcp-iperf-matrix-$(date +%Y%m%d-%H%M%S)}"
APPLY_SYSCTL="${APPLY_SYSCTL:-0}"

ssh_run() {
    local host="$1"
    shift
    ssh ${SSH_OPTS} "${SSH_USER}@${host}" "$@"
}

update_config() {
    local host="$1"
    local config="$2"
    local mtu="$3"
    local wnd="$4"
    local afbuf="$5"
    local retry="$6"
    local wait_ms="$7"
    local tcpbuf="$8"
    local pause="$9"
    local resume="${10}"
    local flush="${11}"
    local frames="${12}"

    ssh_run "${host}" "cd ${KCP_DIR}; \
        cp -n ${config} ${config}.bak-matrix-\$(date +%Y%m%d) 2>/dev/null || true; \
        if ! grep -q '\"kcp\"' ${config}; then \
            perl -0pi -e 's/(\\n\\s*\"node_type\")/\\n    \"kcp\": {\\n        \"mtu\": ${mtu},\\n        \"sndwnd\": ${wnd},\\n        \"rcvwnd\": ${wnd},\\n        \"nodelay\": 1,\\n        \"interval\": 10,\\n        \"resend\": 2,\\n        \"nc\": 1\\n    },\\1/' ${config}; \
        fi; \
        perl -0pi -e 's/\"mtu\":\\s*\\d+/\"mtu\": ${mtu}/; \
            s/\"sndwnd\":\\s*\\d+/\"sndwnd\": ${wnd}/; \
            s/\"rcvwnd\":\\s*\\d+/\"rcvwnd\": ${wnd}/; \
            s/\"af_packet_sndbuf\":\\s*\\d+/\"af_packet_sndbuf\": ${afbuf}/g; \
            s/\"af_packet_rcvbuf\":\\s*\\d+/\"af_packet_rcvbuf\": ${afbuf}/g; \
            s/\"af_packet_send_retry_max\":\\s*\\d+/\"af_packet_send_retry_max\": ${retry}/g; \
            s/\"af_packet_send_wait_ms\":\\s*\\d+/\"af_packet_send_wait_ms\": ${wait_ms}/g; \
            s/\"proxy_tcp_sockbuf\":\\s*\\d+/\"proxy_tcp_sockbuf\": ${tcpbuf}/g; \
            s/\"kcp_read_pause_waitsnd\":\\s*\\d+/\"kcp_read_pause_waitsnd\": ${pause}/g; \
            s/\"kcp_read_resume_waitsnd\":\\s*\\d+/\"kcp_read_resume_waitsnd\": ${resume}/g; \
            s/\"kcp_immediate_flush\":\\s*(true|false)/\"kcp_immediate_flush\": ${flush}/g; \
            s/\"max_frames_per_cycle\":\\s*\\d+/\"max_frames_per_cycle\": ${frames}/g' ${config}"
}

restart_kcp() {
    local host="$1"
    local config="$2"
    local log_file="$3"

    ssh_run "${host}" "cd ${KCP_DIR}; \
        pidof kcp-afpacket | xargs -r kill; \
        sleep 2; \
        nohup ${KCP_BIN} ${config} > ${log_file} 2>&1 & \
        sleep 1; \
        tail -12 ${log_file}"
}

start_iperf_server() {
    ssh_run "${SERVER_HOST}" "pidof iperf3 | xargs -r kill; \
        nohup iperf3 -s > /tmp/iperf3-server.log 2>&1 & \
        sleep 0.5; \
        ps -ef | grep '[i]perf3 -s'"
}

apply_sysctl() {
    local host="$1"

    ssh_run "${host}" "sysctl -w net.core.wmem_max=134217728; \
        sysctl -w net.core.rmem_max=134217728; \
        sysctl -w net.core.wmem_default=4194304; \
        sysctl -w net.core.rmem_default=4194304; \
        sysctl -w net.core.netdev_max_backlog=250000; \
        ip link set dev ens19 txqueuelen 10000; \
        sysctl net.core.wmem_max net.core.rmem_max net.core.netdev_max_backlog"
}

run_case() {
    local name="$1"
    local mtu="$2"
    local wnd="$3"
    local afbuf="$4"
    local retry="$5"
    local wait_ms="$6"
    local tcpbuf="$7"
    local pause="$8"
    local resume="$9"
    local flush="${10}"
    local frames="${11}"

    if [[ -n "${CASE_FILTER}" && "${name}" != *"${CASE_FILTER}"* ]]; then
        return 0
    fi

    mkdir -p "${RESULT_DIR}"

    echo
    echo "===== CASE ${name} ====="
    echo "mtu=${mtu} wnd=${wnd} afbuf=${afbuf} retry=${retry} wait_ms=${wait_ms} tcpbuf=${tcpbuf} pause=${pause} resume=${resume} flush=${flush} frames=${frames}"

    update_config "${FRONTEND_HOST}" "${FRONTEND_CONFIG}" "${mtu}" "${wnd}" "${afbuf}" "${retry}" "${wait_ms}" "${tcpbuf}" "${pause}" "${resume}" "${flush}" "${frames}"
    update_config "${BACKEND_HOST}" "${BACKEND_CONFIG}" "${mtu}" "${wnd}" "${afbuf}" "${retry}" "${wait_ms}" "${tcpbuf}" "${pause}" "${resume}" "${flush}" "${frames}"

    restart_kcp "${FRONTEND_HOST}" "${FRONTEND_CONFIG}" "/tmp/kcp-node-b.log"
    restart_kcp "${BACKEND_HOST}" "${BACKEND_CONFIG}" "/tmp/kcp-node-c.log"

    ssh_run "${CLIENT_HOST}" "iperf3 -c ${FRONTEND_HOST} -P ${PARALLEL} -t ${TEST_SECONDS}" \
        | tee "${RESULT_DIR}/${name}.log"

    awk -v name="${name}" '/sender|receiver/ {print name " " $0}' "${RESULT_DIR}/${name}.log" \
        | tee -a "${RESULT_DIR}/summary.txt"
}

main() {
    mkdir -p "${RESULT_DIR}"
    echo "Result directory: ${RESULT_DIR}"
    echo "Topology: ${CLIENT_HOST} -> ${FRONTEND_HOST} -> ${BACKEND_HOST} -> ${SERVER_HOST}:${SERVER_PORT}"

    if [[ "${APPLY_SYSCTL}" == "1" ]]; then
        echo "Applying temporary sysctl tuning on B/C"
        apply_sysctl "${FRONTEND_HOST}"
        apply_sysctl "${BACKEND_HOST}"
    fi

    start_iperf_server

    # name mtu wnd afbuf retry wait_ms tcpbuf pause resume flush frames
    run_case base4096      1400 1024 16777216  8 1  4194304 4096 2048 true  100000
    run_case p2048        1400 1024 16777216  8 1  4194304 2048 1024 true  100000
    run_case p8192        1400 1024 16777216  8 1  4194304 8192 4096 true  100000
    run_case retry0       1400 1024 16777216  0 0  4194304 4096 2048 true  100000
    run_case frames8192   1400 1024 16777216  8 1  4194304 4096 2048 true  8192
    run_case bigbuf2048   1400 1024 67108864 16 1 16777216 2048 1024 true  100000
    run_case noflush1024  1400 1024 67108864 16 1 16777216 1024 512  false 100000
    run_case kcp1478w4096 1478 4096 16777216  8 1  4194304 4096 2048 true  100000
    run_case kcp1478w8192 1478 8192 16777216  8 1  4194304 4096 2048 true  100000
    run_case kcp1400w4096 1400 4096 16777216  8 1  4194304 4096 2048 true  100000

    echo
    echo "Summary: ${RESULT_DIR}/summary.txt"
}

main "$@"
