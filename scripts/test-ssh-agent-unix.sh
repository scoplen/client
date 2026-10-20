#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq -o Acquire::Retries=0 -o Acquire::http::Timeout=30
apt-get install -y -qq --no-install-recommends openssh-client openssh-server >/dev/null
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_TARGET_DIR=/tmp/scoplen-agent-target
cargo build --locked -p scoplen-client-core --example ssh_agent_smoke
binary="$CARGO_TARGET_DIR/debug/examples/ssh_agent_smoke"

scratch="$(mktemp -d /tmp/scoplen-client-agent.XXXXXXXX)"
sshd_pid=''
agent_pid=''
cleanup() {
    [[ -z "$sshd_pid" ]] || kill "$sshd_pid" 2>/dev/null || true
    [[ -z "$agent_pid" ]] || kill "$agent_pid" 2>/dev/null || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT
useradd -m -s /bin/sh scoplen
printf 'scoplen:disposable-test-password\n' | chpasswd
mkdir -p /run/sshd /home/scoplen/.ssh
for key in host user other; do
    ssh-keygen -q -t ed25519 -N '' -f "$scratch/$key"
done
cp "$scratch/user.pub" /home/scoplen/.ssh/authorized_keys
chown -R scoplen:scoplen /home/scoplen/.ssh
chmod 700 /home/scoplen/.ssh
chmod 600 /home/scoplen/.ssh/authorized_keys
cat > "$scratch/sshd_config" <<SSHD
Port 2222
ListenAddress 127.0.0.1
HostKey $scratch/host
PasswordAuthentication no
PubkeyAuthentication yes
SSHD
/usr/sbin/sshd -t -f "$scratch/sshd_config"
/usr/sbin/sshd -D -e -f "$scratch/sshd_config" &
sshd_pid=$!
eval "$(ssh-agent -s -a "$scratch/agent.sock")" >/dev/null
agent_pid="$SSH_AGENT_PID"
# Load an unrelated identity first: selection must never silently use it.
ssh-add "$scratch/other" "$scratch/user" >/dev/null 2>&1

for _ in $(seq 1 50); do
    if (echo >/dev/tcp/127.0.0.1/2222) 2>/dev/null; then break; fi
    kill -0 "$sshd_pid"
    sleep 0.1
done
run_case() {
    timeout --kill-after=3s 20s "$binary" "$1" 127.0.0.1 2222 scoplen "$2"
}
run_case success "$scratch/user.pub"
run_case untrusted "$scratch/user.pub"
ssh-add -d "$scratch/user" >/dev/null 2>&1
run_case missing "$scratch/user.pub"
ssh-add "$scratch/user" >/dev/null 2>&1
run_case success "$scratch/user.pub"
SSH_AUTH_SOCK="$scratch/absent.sock" run_case unavailable "$scratch/user.pub"
for mode in refused disconnected timeout cancel; do
    SSH_AUTH_SOCK="$scratch/fake-$mode.sock" run_case "$mode" "$scratch/user.pub"
    run_case success "$scratch/user.pub"
done
