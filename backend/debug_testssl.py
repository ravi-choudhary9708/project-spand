import json
with open('/tmp/debug_test.json', 'r') as f:
    data = json.load(f)
for entry in data:
    eid = entry.get('id', '')
    finding = entry.get('finding', '')
    if any(k in eid for k in ['cert_issuer', 'cert_notAfter', 'cert_keySize', 'cert_sign', 'cert_common', 'cert_subj', 'cert_serial']):
        print(f"{eid} => {finding[:150]}")
