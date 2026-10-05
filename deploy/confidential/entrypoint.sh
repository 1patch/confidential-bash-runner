#!/bin/bash
set -euo pipefail

# Tinfoil gives the trusted supervisor a private cgroup namespace. Move its
# processes below that namespace root so Linux can enable sibling controllers
# for individual gVisor sandboxes. No tenant receives this mount or privilege.
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
test "$(cat /proc/self/cgroup)" = '0::/'
mkdir /sys/fs/cgroup/supervisor
while read -r pid; do
  printf '%s\n' "$pid" > /sys/fs/cgroup/supervisor/cgroup.procs
done < /sys/fs/cgroup/cgroup.procs
printf '+cpu +memory +pids\n' > /sys/fs/cgroup/cgroup.subtree_control
exec "$@"
