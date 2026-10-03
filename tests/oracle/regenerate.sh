#!/bin/sh
# Regenerates the oracle: what audit-userspace's own tools (ausearch,
# aureport) make of every fixture, times in UTC. Run it where no account
# resolves the logs' ids to local names, as the outputs here were made
# (audit 4.0.2, Debian 13), from the crate root:
#
#   docker run --rm -v "$PWD:/w" -w /w debian:trixie sh -c \
#     'apt-get update -qq && apt-get install -y -qq auditd && sh tests/oracle/regenerate.sh'
set -eu
export TZ=UTC LC_ALL=C PATH="/usr/sbin:/sbin:$PATH"
cd "$(dirname "$0")/../fixtures"
out=../oracle
for log in */*.log; do
    name=$(echo "$log" | tr / -)
    name=${name%.log}
    # --input-logs off: read this file only. Exit status 1 means "no matches".
    ausearch --input "$log" --interpret --line-buffered > "$out/$name.ausearch" 2>&1 || true
    {
        for report in --summary --login --auth --mods --executable --syscall --comm --host; do
            echo "### aureport $report"
            aureport --input "$log" --interpret $report 2>&1 || true
        done
    } > "$out/$name.aureport"
done
