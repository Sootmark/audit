"""Writes plaso.tsv from psort's JSON lines (see README): one line per
plaso event, sorted: the log file's name, the time (ISO 8601 to the
100 ns, local times as plaso stores them, as if UTC, so without a zone),
what plaso calls that time, the parser, then every value plaso read, as
name=value, sorted by name (plaso's own formatted message, and its
bookkeeping, left out). Independent of this crate: no code shared.

Run: python3 -I tests/oracle/plaso.py out.jsonl > tests/oracle/plaso.tsv
"""

import datetime
import json
import sys

# plaso's bookkeeping, and its formatted message: not values it read.
SKIPPED = {
    "__container_type__",
    "__type__",
    "data_type",
    "date_time",
    "display_name",
    "message",
    "parser",
    "pathspec",
    "sha256_hash",
    "timestamp",
    "timestamp_desc",
}


def iso(micros):
    moment = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=micros)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond:06d}0"


def text(value):
    if isinstance(value, list):
        return ", ".join(text(v) for v in value)
    return str(value).replace("\n", "\\n").replace("\t", "\\t")


def line(event):
    name = event["pathspec"]["location"].rsplit("/", 1)[-1]
    values = [
        f"{key}={text(value)}"
        for key, value in sorted(event.items())
        if key not in SKIPPED and value is not None
    ]
    return "\t".join(
        [name, iso(event["timestamp"]), event["timestamp_desc"], event["parser"]] + values
    )


def main(path):
    with open(path, encoding="utf-8") as events:
        lines = sorted(line(json.loads(event)) for event in events if event.strip())
    sys.stdout.write("".join(f"{line}\n" for line in lines))


main(sys.argv[1])
