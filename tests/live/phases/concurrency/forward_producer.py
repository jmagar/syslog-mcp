#!/usr/bin/env python3
"""Receipt-backed producer for the direct concurrency run.

Plain syslog over TCP has no application acknowledgement: a completed sendall
only proves a socket (here toxiproxy's) took the bytes. The receipt-backed
forward route answers only after the record is durably stored, so a record
counts as accepted here only when the server returns its idempotency key as a
receipt. That is the guarantee the zero-loss-after-accept invariant can hold.
"""
import argparse, json, time, urllib.error, urllib.request

p = argparse.ArgumentParser()
p.add_argument('--port', type=int, required=True)
p.add_argument('--token', required=True)
p.add_argument('--prefix', required=True)
p.add_argument('--count', type=int, required=True)
p.add_argument('--delay', type=float, default=0.05)
a = p.parse_args()
assert 1 <= a.count <= 1000
instance = f'{a.prefix}-forwarder'
sent, failed = [], []
for i in range(a.count):
    marker = f'{a.prefix}-{i:05d}'
    key = f'{instance}-{i + 1}'
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    body = json.dumps({'records': [{
        'source_instance': instance, 'source_epoch': 1, 'sequence': i + 1,
        'idempotency_key': key, 'observed_at': now,
        'line': f'<134>1 {now} {instance} forwarder 15 ID54 - {marker}',
    }], 'gaps': []}).encode()
    request = urllib.request.Request(
        f'http://127.0.0.1:{a.port}/v1/syslog-forward', data=body, method='POST',
        headers={'Host': 'localhost', 'Authorization': f'Bearer {a.token}',
                 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            receipts = json.loads(response.read() or b'{}').get('receipts')
            (sent if response.status == 200 and receipts == [key] else failed).append(marker)
    except (urllib.error.URLError, OSError, ValueError):
        failed.append(marker)
    time.sleep(a.delay)
print(json.dumps({'schema': 'cortex-live-forward-producer-v1', 'offered': a.count,
                  'attempted': len(sent) + len(failed), 'accepted': len(sent),
                  'rejected': len(failed), 'sent': sent, 'failed': failed},
                 separators=(',', ':')))
