#!/bin/bash
# Synthetic activity for the sootmark-audit fixture, on the lab VM, by a
# sudoer. The activity runs with login uid 1000 (as after a PAM login), and
# the syscall rules only follow processes with a login uid, so other work on
# the VM stays out of the log. Leaves ~/sootmark-open/audit/gen/audit.log.
set -u
here=$(cd "$(dirname "$0")" && pwd)
out="$here/gen"
mkdir -p "$out"
log=/var/log/audit/audit.log
user=sootmarktest
logged_in="-F auid>=1000 -F auid!=unset"

sudo kill -USR1 "$(pidof auditd)" # rotate: start from an empty file
sleep 1

sudo auditctl -a always,exit -F arch=b64 -S execve,execveat $logged_in -k exec
sudo auditctl -a always,exit -F arch=b64 -S connect $logged_in -k net
sudo auditctl -w /etc/passwd -p wa -k passwd
sudo auditctl -w /etc/shadow -p wa -k shadow
mkdir -p /tmp/sootmark
sudo auditctl -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2,chmod,fchmodat \
    -F dir=/tmp/sootmark $logged_in -k files
sudo /usr/sbin/sshd -o UsePAM=yes -o ListenAddress=127.0.0.1 -p 2222 -o PidFile=/run/sootmark-sshd.pid
sleep 1

# A process that writes its own login uid, then becomes the user.
sudo bash -c "echo 1000 > /proc/self/loginuid && exec sudo -u $(id -un) bash '$here/activity.sh' '$user'"

sleep 1
sudo kill "$(sudo cat /run/sootmark-sshd.pid)"
sleep 1
sudo loginctl terminate-user "$user" 2>/dev/null; sleep 2
sudo userdel -r "$user" 2>/dev/null
sudo groupdel sootmarkops 2>/dev/null
rmdir /tmp/sootmark
sleep 1
sudo auditctl -D
sleep 1
sudo cat "$log" > "$out/audit.log"
# The log is published: the account that ran this and the machine go by
# other names, as written and hex-encoded (either case).
python3 - "$out/audit.log" "$(id -un)" analyst "$(hostname)" lab-01 <<'PY'
import sys
path, *pairs = sys.argv[1:]
data = open(path, "rb").read()
for old, new in zip(pairs[::2], pairs[1::2]):
    for encode in (str.encode, lambda t: t.encode().hex().encode(), lambda t: t.encode().hex().upper().encode()):
        data = data.replace(encode(old), encode(new))
open(path, "wb").write(data)
PY
wc -c "$out/audit.log"
