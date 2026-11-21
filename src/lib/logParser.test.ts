import test from 'node:test';
import assert from 'node:assert/strict';
import {isPrivateIp, maskPrivateIp, parseLogs, sha256Hex} from './logParser';

test('sha256Hex matches FIPS 180-4 test vector', () => {
  assert.equal(
    sha256Hex('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
  assert.equal(
    sha256Hex(''),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
});

test('maskPrivateIp masks RFC1918 addresses and preserves public IPs', () => {
  assert.equal(isPrivateIp('10.14.0.12'), true);
  assert.equal(maskPrivateIp('10.14.0.12'), '10.14.x.12 (internal-masked)');
  assert.equal(isPrivateIp('203.0.113.45'), false);
  assert.equal(maskPrivateIp('203.0.113.45'), '203.0.113.45');
});

test('parseLogs extracts SSH auth, UFW firewall, Nginx, DNS, CSV, and JSONL entries', () => {
  const mixed = [
    'Nov 20 22:14:09 mum-ssh-01 sshd[4410]: Failed password for invalid user admin from 203.0.113.45 port 54120 ssh2',
    'Nov 20 22:14:15 edge-fw kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.204 DST=10.20.4.18 LEN=60 PROTO=TCP SPT=49012 DPT=5432',
    '192.0.2.134 - - [20/Nov/2026:22:15:00 +0000] "GET /wp-login.php HTTP/1.1" 403 1842 "-" "curl/8.4.0"',
    '20-Nov-2026 22:16:00 client 198.51.100.77#51234: query: c2-sync-beacon.example.net IN A',
    '{"source_ip":"192.0.2.211","destination_ip":"10.32.8.44","destination_port":443,"protocol":"TCP","bytes_transferred":900000000,"event_type":"data_exfiltration","action":"EGRESS_SPIKE"}',
  ].join('\n');

  const parsed = parseLogs(mixed, 'auto', 'unit_test');
  assert.equal(parsed.length, 5);
  assert.equal(parsed[0].eventType, 'ssh_brute_force');
  assert.equal(parsed[0].username, 'admin');
  assert.equal(parsed[1].eventType, 'port_scan');
  assert.equal(parsed[1].maskedDestinationIp, '10.20.x.18 (internal-masked)');
  assert.equal(parsed[2].protocol, 'HTTPS');
  assert.equal(parsed[3].eventType, 'malware_c2');
  assert.equal(parsed[3].domain, 'c2-sync-beacon.example.net');
  assert.equal(parsed[4].eventType, 'data_exfiltration');
  assert.equal(parsed[0].evidenceSha256.length, 64);
});

test('parseLogs handles CSV log uploads cleanly', () => {
  const csv = [
    'timestamp,source_ip,destination_ip,destination_port,protocol,bytes,event_type,action',
    '2026-11-20T22:00:00Z,203.0.113.45,10.14.0.12,22,SSH,2048,ssh_brute_force,FAILED',
  ].join('\n');
  const parsed = parseLogs(csv, 'csv', 'csv_test');
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].sourceIp, '203.0.113.45');
  assert.equal(parsed[0].destinationPort, 22);
});
