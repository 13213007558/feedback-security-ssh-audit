'''
   Offline consistency checks between the built-in policies (builtin_policies.py)
   and the algorithm database (ssh2_kexdb.py).

   Added 2026-11-11 after an offline policy/database consistency review.  These
   tests encode the invariants verified during that review, including the
   documented intentional compatibility exceptions (see
   .feedback/maintenance-2026-11-11-policy-db-consistency.md).
'''
import copy
import re
import threading

import pytest

from ssh_audit.algorithms import Algorithms
from ssh_audit.builtin_policies import BUILTIN_POLICIES
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.writebuf import WriteBuf


# Maps a BUILTIN_POLICIES list field to its algorithm type in SSH2_KexDB.
_FIELD_TO_ALG_TYPE = {
    'host_keys': 'key',
    'optional_host_keys': 'key',
    'kex': 'kex',
    'ciphers': 'enc',
    'macs': 'mac',
}

# Pseudo-algorithms that are only valid for one direction (RFC 8308 & Terrapin strict-kex markers).
_CLIENT_ONLY_KEX = ['ext-info-c', 'kex-strict-c-v00@openssh.com']
_SERVER_ONLY_KEX = ['ext-info-s', 'kex-strict-s-v00@openssh.com']

# Intentional compatibility exceptions, verified during the 2026-11-11 review.
#
# Historical (pre-post-quantum) policy versions pin key exchanges that the
# database flags as not post-quantum safe.  A fully compliant target therefore
# receives del/chg recommendations for algorithms its policy requires.  This is
# by design: policies are point-in-time hardening snapshots, while
# recommendations reflect current best practice.  PQ-only alternatives exist as
# newer policy versions (Debian 13, Rocky Linux 10, Ubuntu 26.04, OpenSSH v10.x).
_INTENTIONAL_DEL_KEX = [
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
]
_INTENTIONAL_CHG_KEX = ['diffie-hellman-group-exchange-sha256']

# The sntrup761x25519-sha512@openssh.com key exchange first appeared in OpenSSH
# 8.5, but the v8.5-v8.7 policy snapshots predate its adoption in the hardening
# guides (it is required starting with the v8.8 policies).  The report
# legitimately recommends adding it to targets pinned to those older policies.
_INTENTIONAL_ADD_KEX_BY_POLICY = {
    'Hardened OpenSSH Server v8.5 (version 4)': ['sntrup761x25519-sha512@openssh.com'],
    'Hardened OpenSSH Server v8.6 (version 4)': ['sntrup761x25519-sha512@openssh.com'],
    'Hardened OpenSSH Server v8.7 (version 4)': ['sntrup761x25519-sha512@openssh.com'],
    # OpenSSH 10.4 ships this host key as an experimental non-default option;
    # the policy deliberately excludes it until it is considered stable (see
    # the note in builtin_policies.py).  PENDING maintainer confirmation
    # whether the database should carry WARN_EXPERIMENTAL for it.
    'Hardened OpenSSH Server v10.4 (version 1)': ['ssh-mldsa44-ed25519@openssh.com'],
}


def _policy_algorithms(policy_struct, field):
    return policy_struct.get(field) or []


def _build_kex(policy_struct):
    '''Builds a mock SSH2_Kex that exactly matches a built-in policy's algorithm lists.'''
    w = WriteBuf()
    w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
    w.write_list(policy_struct['kex'])
    w.write_list(policy_struct['host_keys'])
    w.write_list(policy_struct['ciphers'])
    w.write_list(policy_struct['ciphers'])
    w.write_list(policy_struct['macs'])
    w.write_list(policy_struct['macs'])
    w.write_list(['none'])
    w.write_list(['none'])
    w.write_list([''])
    w.write_list([''])
    w.write_byte(False)
    w.write_int(0)
    return SSH2_Kex.parse(OutputBuffer, w.write_flush())


def _software_for(policy_name):
    '''Returns a Software object for OpenSSH server policies, or None (unknown software) otherwise.'''
    m = re.search(r'OpenSSH Server v(\d+\.\d+)', policy_name)
    if m:
        return Software(None, Product.OpenSSH, m.group(1), None, None)
    return None


class TestPolicyDBConsistency:
    @pytest.fixture(autouse=True)
    def init(self):
        # Other test modules mutate the thread-local database copy (e.g., the
        # Terrapin post-processing in test_ssh2.py).  Reset it so these
        # consistency checks always run against the pristine MASTER_DB.
        SSH2_KexDB.DB_PER_THREAD[threading.get_ident()] = copy.deepcopy(SSH2_KexDB.MASTER_DB)
        self.db = SSH2_KexDB.get_db()

    def test_no_dangling_policy_references(self):
        '''Every algorithm referenced by a built-in policy must exist in the algorithm database.'''
        dangling = []
        for policy_name, policy_struct in BUILTIN_POLICIES.items():
            for field, alg_type in _FIELD_TO_ALG_TYPE.items():
                for alg in _policy_algorithms(policy_struct, field):
                    if alg not in self.db[alg_type]:
                        dangling.append('%s: %s (%s)' % (policy_name, alg, field))
            for hostkey_type in (policy_struct.get('hostkey_sizes') or {}):
                if hostkey_type not in self.db['key']:
                    dangling.append('%s: %s (hostkey_sizes)' % (policy_name, hostkey_type))
            for dh_type in (policy_struct.get('dh_modulus_sizes') or {}):
                if dh_type not in self.db['kex']:
                    dangling.append('%s: %s (dh_modulus_sizes)' % (policy_name, dh_type))
        assert dangling == []

    def test_no_policy_allowed_algorithm_fails(self):
        '''No algorithm allowed by a built-in policy may be marked as a failure in the database.'''
        failures = []
        for policy_name, policy_struct in BUILTIN_POLICIES.items():
            for field, alg_type in _FIELD_TO_ALG_TYPE.items():
                for alg in _policy_algorithms(policy_struct, field):
                    entry = self.db[alg_type][alg]
                    if len(entry) > 1 and len(entry[1]) > 0:
                        failures.append('%s: %s -> %s' % (policy_name, alg, entry[1]))
        assert failures == []

    def test_db_reason_slot_discipline(self):
        '''FAIL_* reasons only in the failures slot, WARN_* only in warnings, INFO_* only in info.'''
        reason_kind = {}
        for const_name in dir(SSH2_KexDB):
            if const_name.startswith(('FAIL_', 'WARN_', 'INFO_')):
                reason_kind[getattr(SSH2_KexDB, const_name)] = const_name.split('_')[0]
        misplaced = []
        for alg_type in self.db:
            for alg_name, entry in self.db[alg_type].items():
                for slot, expected in ((1, 'FAIL'), (2, 'WARN'), (3, 'INFO')):
                    if len(entry) <= slot:
                        continue
                    for reason in entry[slot]:
                        if reason_kind.get(reason) != expected:
                            misplaced.append('%s: %s slot %d: %s' % (alg_type, alg_name, slot, reason))
        assert misplaced == []

    def test_kex_direction_matches_policy_type(self):
        '''Server policies must use -s pseudo-algorithms only; client policies -c only.'''
        mismatched = []
        for policy_name, policy_struct in BUILTIN_POLICIES.items():
            kex = policy_struct['kex'] or []
            if policy_struct['server_policy']:
                mismatched += ['%s: %s' % (policy_name, a) for a in kex if a in _CLIENT_ONLY_KEX]
            else:
                mismatched += ['%s: %s' % (policy_name, a) for a in kex if a in _SERVER_ONLY_KEX]
        assert mismatched == []

    def test_dh_modulus_sizes_subset_of_kex(self):
        '''dh_modulus_sizes entries must correspond to key exchanges the policy actually allows.'''
        stale = []
        for policy_name, policy_struct in BUILTIN_POLICIES.items():
            kex = set(policy_struct['kex'] or [])
            for dh_type in (policy_struct.get('dh_modulus_sizes') or {}):
                if dh_type not in kex:
                    stale.append('%s: %s' % (policy_name, dh_type))
        assert stale == []

    def test_xmss_experimental_is_warning_not_failure(self):
        '''Regression: ssh-xmss algorithms are experimental (warning), not failures.'''
        for alg in ['ssh-xmss@openssh.com', 'ssh-xmss-cert-v01@openssh.com']:
            entry = self.db['key'][alg]
            assert entry[0] == ['7.7']  # Product version annotation must be preserved.
            assert entry[1] == []
            assert SSH2_KexDB.WARN_EXPERIMENTAL in entry[2]

    def test_recommendation_conflicts_limited_to_intentional_exceptions(self):
        '''A target fully compliant with a built-in policy must only produce the
        documented intentional recommendation/policy conflicts.'''
        unexpected = []
        for policy_name, policy_struct in BUILTIN_POLICIES.items():
            kex = _build_kex(policy_struct)
            algs = Algorithms(kex)
            software = _software_for(policy_name)
            for_server = bool(policy_struct['server_policy'])
            _, rec = algs.get_recommendations(software, for_server=for_server)
            if 2 not in rec:
                continue
            allowed_adds = _INTENTIONAL_ADD_KEX_BY_POLICY.get(policy_name, [])
            for alg_type, actions in rec[2].items():
                for action, alg_entries in actions.items():
                    for alg_name in alg_entries:
                        if action == 'del' and alg_type == 'kex' and alg_name in _INTENTIONAL_DEL_KEX:
                            continue
                        if action == 'chg' and alg_type == 'kex' and alg_name in _INTENTIONAL_CHG_KEX:
                            continue
                        if action == 'add' and alg_name in allowed_adds:
                            continue
                        unexpected.append('%s: %s %s %s' % (policy_name, action, alg_type, alg_name))
        assert unexpected == []
