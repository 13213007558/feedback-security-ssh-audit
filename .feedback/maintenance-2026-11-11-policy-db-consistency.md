# Offline Policy/Database Consistency Review — 2026-11-11

Scope: built-in policies (`src/ssh_audit/builtin_policies.py`) and the algorithm
database (`src/ssh_audit/ssh2_kexdb.py`) only.  No external hosts were scanned;
no vulnerability data was added from outside the repository.  Every finding was
reproduced offline with mock KEX data built via `WriteBuf`/`SSH2_Kex.parse`
(the same technique as `test/test_policy.py`).

Regression samples: `test/test_policy_db_consistency.py` (7 tests).

## 1. Data errors fixed (minimal changes)

### 1.1 `ssh-xmss@openssh.com` / `ssh-xmss-cert-v01@openssh.com`: WARN_EXPERIMENTAL in the failures slot

- **Evidence (in-repo):** the entry format is
  `[[versions], [failures], [warnings], [info]]` (comment at `ssh2_kexdb.py:95`).
  `WARN_EXPERIMENTAL` is defined among the warning constants (`ssh2_kexdb.py:59`),
  and was the only `WARN_*` constant sitting in a failures slot anywhere in the
  database.  The directly comparable experimental key exchange
  `sntrup4591761x25519-sha512@tinyssh.org` carries `WARN_EXPERIMENTAL` in its
  warnings slot (`ssh2_kexdb.py:210`).
- **Impact before fix:** the recommendation engine weights failures 10x
  (`algorithms.py:144-150`), so these host keys were reported as *failures* and
  drew a critical-level `del` recommendation instead of a warning-level one.
- **Reproduction (mock KEX offering only the two xmss host keys):**
  - before: `failures=['using experimental algorithm']`, `del` recommendation at 10 points (critical)
  - after: `failures=[] warnings=['using experimental algorithm']`, `del` recommendation at 1 point (warning)
- **Fix:** `src/ssh_audit/ssh2_kexdb.py` — moved `WARN_EXPERIMENTAL` to the
  warnings slot for both entries.  The `[['7.7']]` product-version annotation
  is unchanged.

### 1.2 Stale `dh_modulus_sizes` in three post-quantum-only server policies

- **Affected:** `Hardened Debian 13 (version 1)`, `Hardened Rocky Linux 10
  (version 1)`, `Hardened Ubuntu Server 26.04 LTS (version 1)`.
- **Evidence (in-repo):** all three policies removed
  `diffie-hellman-group-exchange-sha256` from their `kex` lists, and their
  changelogs state that group-exchange algorithms are no longer used and
  `/etc/ssh/moduli` editing was dropped.  The sibling PQ-only policies
  (`Hardened OpenSSH Server v10.0`–`v10.4`) already use
  `'dh_modulus_sizes': {}`.  The leftover
  `{'diffie-hellman-group-exchange-sha256': 3072}` was unreachable dead data:
  `Policy.evaluate` (`policy.py:458-468`) only checks modulus sizes for
  algorithms the target actually negotiated, and any target offering
  group-exchange already fails the exact-match kex check.
- **Fix:** `src/ssh_audit/builtin_policies.py` — set `'dh_modulus_sizes': {}`
  in the three policies.  Behavior-neutral for compliant targets.

## 2. Intentional compatibility exceptions (kept, with rationale)

Verified by simulating a fully compliant target for every built-in policy
(server and client directions) and diffing the report recommendations against
the policy's algorithm lists.  The only conflicts are:

1. **Pre-PQ policy versions vs `WARN_NOT_PQ_SAFE`.**  Historical policy
   versions require `curve25519-sha256`, `curve25519-sha256@libssh.org`,
   `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`
   (`del`, warning level) and `diffie-hellman-group-exchange-sha256`
   (`chg` to >= 3072-bit modulus).  Kept: policies are point-in-time hardening
   snapshots pinned to what each OS/OpenSSH release shipped; PQ-only
   alternatives exist as newer policy versions (Debian 13, Rocky Linux 10,
   Ubuntu 26.04, OpenSSH v10.x).  Removing the older versions would break
   audits of long-term-support systems.
2. **`add sntrup761x25519-sha512@openssh.com` for OpenSSH v8.5–v8.7 policies.**
   The algorithm first appeared in OpenSSH 8.5, but those policy snapshots
   predate its adoption in the hardening guides (required starting with the
   v8.8 policies).  Kept: same historical-snapshot rationale.

## 3. Items pending maintainer confirmation (not changed)

1. **`ssh-mldsa44-ed25519@openssh.com` recommended but policy-excluded.**
   For a target compliant with `Hardened OpenSSH Server v10.4 (version 1)`,
   the report recommends `add ssh-mldsa44-ed25519@openssh.com`, while the
   policy deliberately omits it — the note at `builtin_policies.py:128` says
   it is an experimental non-default option that will become a requirement
   once no longer experimental.  The database entry
   (`ssh2_kexdb.py:276`) carries no `WARN_EXPERIMENTAL`, unlike the analogous
   experimental `sntrup4591761x25519-sha512@tinyssh.org`.  Proposed options:
   (a) add `WARN_EXPERIMENTAL` to its warnings slot (also suppresses the
   `add` recommendation), or (b) accept the recommendation as-is.  Not changed
   because either choice alters scan output for OpenSSH 10.4–10.5 servers and
   is a product decision.
2. **`diffie-hellman_group17-sha512` (underscore variant, `ssh2_kexdb.py:115`).**
   Duplicates `diffie-hellman-group17-sha512` with a non-standard name;
   unreferenced by any policy or test.  Possibly kept for non-standard
   implementations seen in the wild.  Confirm whether to retain or drop.

## 4. Checks that came back clean

- No dangling references: every algorithm named by any built-in policy
  (host keys, optional host keys, kex, ciphers, MACs, `hostkey_sizes`,
  `dh_modulus_sizes`) exists in the database.
- No policy-allowed algorithm carries a database failure.
- Client/server direction is consistent: server policies use only
  `ext-info-s`/`kex-strict-s-v00@openssh.com`; client policies only
  `ext-info-c`/`kex-strict-c-v00@openssh.com`.
- Server-policy `hostkey_sizes` tables cover all required and optional host
  keys; version annotations parse cleanly.

## 5. Verification

```sh
.venv/bin/python -m pytest -q -o addopts= test/   # 130 passed (was 123 + 7 new)
```

Baseline before changes: `test/test_ssh2.py test/test_policy.py
test/test_banner.py` → 33 passed.  After changes: same 33 pass, plus
`test/test_policy_db_consistency.py` (7 new regression tests), full `test/`
directory 130 passed.
