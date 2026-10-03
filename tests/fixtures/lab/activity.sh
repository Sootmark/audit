#!/bin/bash
# What gen.sh records: run with a login uid set.
set -u
user=$1

# Accounts.
sudo groupadd sootmarkops
sudo useradd -m -s /bin/bash -G sootmarkops "$user"
echo "$user:Correct-Horse-1" | sudo chpasswd
sudo usermod -aG adm "$user"

# Commands: spaces, non-ASCII, quotes, and an argument long enough to be split.
cd /tmp
/bin/echo "hello world" > /dev/null
/bin/echo café "naïve résumé" 'it'"'"'s' > /dev/null
/bin/true "$(head -c 9000 /dev/zero | tr '\0' 'x') tail"
touch /tmp/sootmark/a.txt
chmod 600 /tmp/sootmark/a.txt
mv /tmp/sootmark/a.txt "/tmp/sootmark/b c.txt"
rm "/tmp/sootmark/b c.txt"

# sudo.
sudo -u "$user" /usr/bin/id
sudo /usr/bin/cat /etc/hostname > /dev/null

# Network: IPv4 and IPv6 loopback.
bash -c 'exec 3<>/dev/tcp/127.0.0.1/22; head -c 20 <&3 >/dev/null' || true
python3 -c 'import socket; s=socket.create_connection(("::1", 22)); s.recv(20)' || true

# ssh with a test key to the temporary sshd, and a failed login.
keydir=$(mktemp -d)
ssh-keygen -q -t ed25519 -N '' -f "$keydir/key" -C sootmark-test
sudo install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
sudo install -m 600 -o "$user" -g "$user" "$keydir/key.pub" "/home/$user/.ssh/authorized_keys"
ssh -tt -i "$keydir/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 "$user@127.0.0.1" 'id; /bin/echo "remote cmd"'
ssh -i "$keydir/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 nosuchuser@127.0.0.1 true || true
rm -rf "$keydir"
