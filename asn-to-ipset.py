#!/usr/bin/env python3
import sys
import subprocess
import maxminddb

tmpset = sys.argv[1]
mmdb   = sys.argv[2]
asns   = set(sys.argv[3:])

count = 0
proc = subprocess.Popen(['ipset', 'restore'], stdin=subprocess.PIPE, bufsize=1048576)

buf = [f'flush {tmpset}\n']
BATCH = 500

with maxminddb.open_database(mmdb) as db:
    for network, record in db:
        if not record:
            continue
        if str(record.get('autonomous_system_number', '')) not in asns:
            continue
        if ':' in str(network):
            continue
        buf.append(f'add {tmpset} {network}\n')
        count += 1
        if len(buf) >= BATCH:
            proc.stdin.write(''.join(buf).encode())
            buf = []

if buf:
    proc.stdin.write(''.join(buf).encode())

proc.stdin.close()
proc.wait()

print(count)
