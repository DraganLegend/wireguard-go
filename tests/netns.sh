#!/bin/bash
set -e

# ./netns.sh /path/to/wireguard-go [basic|nat|sticky|all]

exec 3>&1
export WG_HIDE_KEYS=never
export LOG_LEVEL="verbose"

program=$1
mode=${2:-basic}     # 沒給就跑 basic

if [[ -z $program ]]; then
    echo "usage: $0 /path/to/wireguard-go [basic|nat|sticky|all]" >&2
    exit 1
fi

netns0="wg-test-$$-0"
netns1="wg-test-$$-1"
netns2="wg-test-$$-2"

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
n0() { pretty 0 "$*"; maybe_exec ip netns exec $netns0 "$@"; }
n1() { pretty 1 "$*"; maybe_exec ip netns exec $netns1 "$@"; }
n2() { pretty 2 "$*"; maybe_exec ip netns exec $netns2 "$@"; }
ip0() { pretty 0 "ip $*"; ip -n $netns0 "$@"; }
ip1() { pretty 1 "ip $*"; ip -n $netns1 "$@"; }
ip2() { pretty 2 "ip $*"; ip -n $netns2 "$@"; }
sleep() { read -t "$1" -N 0 || true; }
waitiface() {
    pretty "${1//*-}" "wait for $2 to come up"
    ip netns exec "$1" bash -c "while [[ \$(< \"/sys/class/net/$2/operstate\") != up ]]; do read -t .1 -N 0 || true; done;"
}

cleanup() {
    set +e
    exec 2>/dev/null
    printf "$orig_message_cost" > /proc/sys/net/core/message_cost

    ip1 link del dev wg1 2>/dev/null
    ip2 link del dev wg2 2>/dev/null

    ip0 link del dev vethrc 2>/dev/null
    ip0 link del dev vethrs 2>/dev/null

    ip1 link del dev vethc 2>/dev/null
    ip1 link del dev veth1 2>/dev/null

    ip2 link del dev veths 2>/dev/null
    ip2 link del dev veth2 2>/dev/null

    ip0 link del dev wg0 2>/dev/null

    # 把 netns 裡活著的行程殺掉
    local to_kill="$(ip netns pids $netns0) $(ip netns pids $netns1) $(ip netns pids $netns2)"
    [[ -n $to_kill ]] && kill $to_kill

    pp ip netns del $netns1
    pp ip netns del $netns2
    pp ip netns del $netns0
    exit
}

orig_message_cost="$(< /proc/sys/net/core/message_cost)"
trap cleanup EXIT
printf 0 > /proc/sys/net/core/message_cost

# 先確保乾淨
ip netns del $netns0 2>/dev/null || true
ip netns del $netns1 2>/dev/null || true
ip netns del $netns2 2>/dev/null || true

# 建三個 ns
pp ip netns add $netns0
pp ip netns add $netns1
pp ip netns add $netns2

# 每個 ns 都要有 /dev/net/tun
for ns in $netns0 $netns1 $netns2; do
    ip netns exec $ns mkdir -p /dev/net
    ip netns exec $ns bash -c '[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200'
    ip netns exec $ns chmod 0666 /dev/net/tun
done

# ns0 的 lo 要起來
ip0 link set up dev lo

# === 共用的 key ===
key1="$(pp wg genkey)"
key2="$(pp wg genkey)"
pub1="$(pp wg pubkey <<<"$key1")"
pub2="$(pp wg pubkey <<<"$key2")"
psk="$(pp wg genpsk)"

# ------------------------------------
# BASIC：ns1、ns2 自己跑，ns0 當 router
# ------------------------------------
run_basic() {
    pretty "" "=== BASIC PHASE (run in each ns) ==="

    # 1. 在 ns1 / ns2 裡起 wireguard-go
    ip netns exec "$netns1" env WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 WG_PPROF=0 \
        "$program" wg1 >/tmp/wg1.log 2>&1 &
    ip netns exec "$netns2" env WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 WG_PPROF=0 \
        "$program" wg2 >/tmp/wg2.log 2>&1 &

    # 等介面起來
    for i in {1..50}; do ip -n "$netns1" link show wg1 &>/dev/null && break; sleep 0.1; done
    for i in {1..50}; do ip -n "$netns2" link show wg2 &>/dev/null && break; sleep 0.1; done

    # 隧道位址
    ip1 addr add 192.168.241.1/24 dev wg1
    ip1 addr add fd00::1/24 dev wg1
    ip2 addr add 192.168.241.2/24 dev wg2
    ip2 addr add fd00::2/24 dev wg2

    # ---------------------------
    # 兩條 veth，但「不同網段」！！
    # ---------------------------

    # ns1 <-> ns0
    ip0 link add vethrc type veth peer name vethc
    ip0 link set vethc netns "$netns1"
    ip0 addr add 10.0.0.1/24 dev vethrc
    ip0 link set vethrc up
    ip1 addr add 10.0.0.11/24 dev vethc
    ip1 link set vethc up

    # ns2 <-> ns0
    ip0 link add vethrs type veth peer name veths
    ip0 link set veths netns "$netns2"
    ip0 addr add 10.0.1.1/24 dev vethrs
    ip0 link set vethrs up
    ip2 addr add 10.0.1.22/24 dev veths
    ip2 link set veths up

    # 等起來
    waitiface "$netns0" vethrc
    waitiface "$netns0" vethrs
    waitiface "$netns1" vethc
    waitiface "$netns2" veths

    # ns0 當 router
    n0 bash -c 'printf 1 > /proc/sys/net/ipv4/ip_forward'
    n0 iptables -P FORWARD ACCEPT

    # 告訴 ns1：要去 10.0.1.0/24 走 10.0.0.1
    ip1 route add 10.0.1.0/24 via 10.0.0.1 dev vethc
    # 告訴 ns2：要去 10.0.0.0/24 走 10.0.1.1
    ip2 route add 10.0.0.0/24 via 10.0.1.1 dev veths

    # WireGuard 設定（這裡 endpoint 就要用「對方那條的 IP」）
    n1 wg set wg1 \
        private-key <(echo "$key1") \
        listen-port 10000 \
        peer "$pub2" \
            preshared-key <(echo "$psk") \
            endpoint 10.0.1.22:20000 \
            persistent-keepalive 1 \
            allowed-ips 192.168.241.2/32,fd00::2/128

    n2 wg set wg2 \
        private-key <(echo "$key2") \
        listen-port 20000 \
        peer "$pub1" \
            preshared-key <(echo "$psk") \
            endpoint 10.0.0.11:10000 \
            persistent-keepalive 1 \
            allowed-ips 192.168.241.1/32,fd00::1/128

    # 隧道路由保險
    ip1 route add 192.168.241.2/32 dev wg1 2>/dev/null || true
    ip2 route add 192.168.241.1/32 dev wg2 2>/dev/null || true

    ip1 link set up dev wg1
    ip2 link set up dev wg2
    sleep 1

    # 看看兩邊都起來了沒
    n1 wg show wg1
    n2 wg show wg2

    # 試 ping
    if ! n2 ping -c 3 -W 1 192.168.241.1; then
        echo "[!] ping failed, dump logs..." >&3
        echo "---- /tmp/wg1.log ----" >&3
        cat /tmp/wg1.log >&3 || true
        echo "---- /tmp/wg2.log ----" >&3
        cat /tmp/wg2.log >&3 || true
        exit 1
    fi

    n1 ping -c 3 -W 1 192.168.241.2 || true
}

# ----------------
# NAT 段（可選）
# ----------------
run_nat() {
    pretty "" "=== NAT PHASE ==="

    # 如果 basic 被前面清掉，就再起一次
    if ! ip -n $netns1 link show wg1 &>/dev/null; then
        run_basic
    fi

    # 這裡其實可以直接用你原本的 NAT 拓樸
    # ns0 已經能轉發了，上面也打開 FORWARD 了
    # 你可以在這裡再做一層 SNAT / DNAT
    n0 bash -c 'printf 2 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout'
    n0 bash -c 'printf 2 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream'

    # 示範：把 192.168.241.0/24 打到 ns2 那側的 10.0.1.0/24 都 SNAT 成 10.0.1.1
    n0 iptables -t nat -A POSTROUTING -s 192.168.241.0/24 -d 10.0.1.0/24 -j SNAT --to 10.0.1.1

    # 驗一下還能互 ping
    n1 ping -W 1 -c 1 192.168.241.2
    n2 ping -W 1 -c 1 192.168.241.1

    # 清掉 NAT 規則（不然後面 sticky 會髒）
    n0 iptables -t nat -F
}

# ----------------
# sticky 段（可選）
# ----------------
run_sticky() {
    pretty "" "=== STICKY PHASE ==="

    # 確保 basic 還在
    if ! ip -n $netns1 link show wg1 &>/dev/null; then
        run_basic
    fi

    # 做一條 ns1 <-> ns2 的 veth
    ip1 link add veth1 type veth peer name veth2
    ip1 link set veth2 netns $netns2

    n1 bash -c 'printf 0 > /proc/sys/net/ipv6/conf/veth1/accept_dad'
    n2 bash -c 'printf 0 > /proc/sys/net/ipv6/conf/veth2/accept_dad'
    n1 bash -c 'printf 1 > /proc/sys/net/ipv4/conf/veth1/promote_secondaries'

    ip1 addr add 10.0.9.1/24 dev veth1
    ip2 addr add 10.0.9.2/24 dev veth2
    ip1 link set veth1 up
    ip2 link set veth2 up
    waitiface $netns1 veth1
    waitiface $netns2 veth2

    # 改成走這條 endpoint
    n1 wg set wg1 peer "$pub2" endpoint 10.0.9.2:20000
    n2 wg set wg2 peer "$pub1" endpoint 10.0.9.1:10000

    n2 ping -W 1 -c 1 192.168.241.1
}

# ----------------- 主流程 -----------------
case "$mode" in
    basic)
        run_basic
        ;;
    nat)
        run_basic
        run_nat
        ;;
    sticky)
        run_basic
        run_sticky
        ;;
    all)
        run_basic
        run_nat
        run_sticky
        ;;
    *)
        echo "usage: $0 /path/to/wireguard-go [basic|nat|sticky|all]" >&2
        exit 1
        ;;
esac

pretty "" "Done ($mode)"