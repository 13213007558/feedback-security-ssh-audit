"""Tests for the machine-readable evidence classification.

These exercise offline banner/KEX combinations and assert that the text and
JSON representations never contradict each other, and that observed weak
algorithms are never downgraded merely because the banner is uncertain.
"""
import os
import pytest

from ssh_audit.banner import Banner
from ssh_audit.evidence import EvidenceType
from ssh_audit.evidence import build_evidence
from ssh_audit.evidence import render_text_evidence
from ssh_audit.evidence import summarize_evidence
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kexparty import SSH2_KexParty


# pylint: disable=attribute-defined-outside-init
class TestEvidence:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.ssh_audit = ssh_audit

    @staticmethod
    def _make_kex(kex_algs=None, key_algs=None, enc=None, mac=None):
        kex_algs = kex_algs or []
        key_algs = key_algs or []
        enc = enc or []
        mac = mac or []
        cli = SSH2_KexParty(enc, mac, ['none'], [])
        srv = SSH2_KexParty(enc, mac, ['none'], [])
        return SSH2_Kex(OutputBuffer, os.urandom(16), kex_algs, key_algs,
                        cli, srv, 0)

    @staticmethod
    def _parse(raw_banner):
        banner = Banner.parse(raw_banner)
        return banner, Software.parse(banner)

    # --- Fingerprint / inference classification -----------------------------

    def test_unparseable_banner_is_undetermined(self):
        banner, software = self._parse('SSH-2.0-WeirdSSH')
        evidence = build_evidence(banner, software, None)
        inference = evidence['fingerprint']['inference']
        assert inference['status'] == EvidenceType.UNDETERMINED
        assert evidence['fingerprint']['parsed'] is None
        assert evidence['fingerprint']['raw_banner_software'] == 'WeirdSSH'

    def test_clean_upstream_banner_is_inference(self):
        banner, software = self._parse('SSH-2.0-OpenSSH_9.6')
        evidence = build_evidence(banner, software, None)
        inference = evidence['fingerprint']['inference']
        assert inference['status'] == EvidenceType.BANNER_INFERENCE
        assert evidence['fingerprint']['parsed']['version'] == '9.6'
        assert evidence['fingerprint']['parsed']['patch'] is None

    def test_portable_p_suffix_is_not_flagged_as_backport(self):
        banner, software = self._parse('SSH-2.0-OpenSSH_8.4p1')
        evidence = build_evidence(banner, software, None)
        reasons = ' '.join(evidence['fingerprint']['inference']['reasons'])
        assert 'back-port' not in reasons
        assert evidence['fingerprint']['parsed']['patch'] == 'p1'

    def test_distribution_suffix_is_flagged(self):
        # Distribution comments indicate a repackaged build that may back-port.
        banner, software = self._parse(
            'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1')
        evidence = build_evidence(banner, software, None)
        reasons = ' '.join(evidence['fingerprint']['inference']['reasons'])
        assert 're-packaged' in reasons or 're-brand' in reasons
        # The raw fingerprint is preserved verbatim.
        assert evidence['fingerprint']['raw_banner_comments'] == \
            'Debian-5+deb11u1'

    def test_vendor_rebrand_preserves_vendor_and_product(self):
        banner, software = self._parse('SSH-2.0-mpSSH_0.2.1')
        evidence = build_evidence(banner, software, None)
        parsed = evidence['fingerprint']['parsed']
        assert parsed['vendor'] == 'HP'
        assert parsed['product'] == 'iLO (Integrated Lights-Out) sshd'
        assert parsed['version'] == '0.2.1'

    def test_non_upstream_patch_flags_possible_backport(self):
        banner, software = self._parse('SSH-2.0-OpenSSH_7.2-hpn14v5')
        evidence = build_evidence(banner, software, None)
        reasons = ' '.join(evidence['fingerprint']['inference']['reasons'])
        assert 'back-port' in reasons
        assert evidence['fingerprint']['parsed']['patch'] == 'hpn14v5'

    def test_missing_version_is_caveated(self):
        # TinySSH stores its identifier without a separate numeric version when
        # the regex cannot extract one; construct a Software with empty version
        # directly to cover the missing-version branch.
        software = Software(None, 'TinySSH', '', None, None)
        evidence = build_evidence(None, software, None)
        reasons = ' '.join(evidence['fingerprint']['inference']['reasons'])
        assert 'no numeric version' in reasons

    # --- Negotiation observations -------------------------------------------

    def test_observed_weak_algorithms_are_negotiation_evidence(self):
        kex = self._make_kex(
            kex_algs=['diffie-hellman-group14-sha1'],
            enc=['aes128-cbc'],
            mac=['hmac-sha1'])
        banner, software = self._parse('SSH-2.0-OpenSSH_8.4p1 Debian-5')
        evidence = build_evidence(banner, software, kex)

        weak = {f['algorithm']: f for f in evidence['findings']
                if 'fail' in f['notes'] or 'warn' in f['notes']}
        # Even though the banner is a back-port-flagged inference, the observed
        # weak algorithms remain direct observations, never downgraded.
        for name in ('diffie-hellman-group14-sha1', 'aes128-cbc',
                     'hmac-sha1'):
            assert name in weak
            assert weak[name]['type'] == \
                EvidenceType.NEGOTIATION_OBSERVATION

        # SHA-1 MAC is an observed fail regardless of banner uncertainty.
        assert 'fail' in weak['hmac-sha1']['notes']

    def test_no_banner_based_findings_are_invented(self):
        # With a KEX but no parsed software, findings must still only reflect
        # the negotiated algorithms; nothing extra is fabricated.
        kex = self._make_kex(enc=['aes256-ctr'])
        evidence = build_evidence(None, None, kex)
        assert len(evidence['findings']) == 1
        assert evidence['findings'][0]['algorithm'] == 'aes256-ctr'
        assert evidence['findings'][0]['type'] == \
            EvidenceType.NEGOTIATION_OBSERVATION

    def test_unknown_algorithm_is_still_observed(self):
        kex = self._make_kex(kex_algs=['totally-made-up-kex'])
        evidence = build_evidence(None, None, kex)
        finding = evidence['findings'][0]
        assert finding['algorithm'] == 'totally-made-up-kex'
        assert finding['type'] == EvidenceType.NEGOTIATION_OBSERVATION
        # The same canonical "unknown algorithm" note the legacy JSON emits.
        assert finding['notes']['fail'] == ['using unknown algorithm']

    def test_gss_kex_wildcard_lookup(self):
        kex = self._make_kex(
            kex_algs=['gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg=='])
        evidence = build_evidence(None, None, kex)
        finding = evidence['findings'][0]
        # The wildcard-normalized database entry still yields the SHA-1 fail.
        assert 'fail' in finding['notes']
        assert finding['type'] == EvidenceType.NEGOTIATION_OBSERVATION

    def test_evidence_types_are_stable_identifiers(self):
        evidence = build_evidence(None, None, None)
        assert evidence['evidence_types'] == [
            EvidenceType.NEGOTIATION_OBSERVATION,
            EvidenceType.BANNER_INFERENCE,
            EvidenceType.UNDETERMINED,
        ]

    # --- Text / JSON consistency --------------------------------------------

    def test_text_and_json_do_not_contradict(self):
        kex = self._make_kex(
            kex_algs=['diffie-hellman-group14-sha1'],
            enc=['aes128-cbc'],
            mac=['hmac-sha1'])
        banner, software = self._parse(
            'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1')
        evidence = build_evidence(banner, software, kex)
        text = '\n'.join(render_text_evidence(evidence))

        # Every JSON finding with a fail/warn must appear in the text report,
        # and the text must label it with the same evidence type.
        json_weak = [f for f in evidence['findings']
                     if 'fail' in f['notes'] or 'warn' in f['notes']]
        assert len(json_weak) > 0
        for finding in json_weak:
            needle = '({}) {}'.format(finding['algorithm_type'],
                                      finding['algorithm'])
            assert needle in text
        assert text.count(EvidenceType.NEGOTIATION_OBSERVATION) == \
            len(json_weak)

        # The banner inference status in JSON must match the text line.
        status = evidence['fingerprint']['inference']['status']
        assert 'version evidence type: {}'.format(status) in text

    def test_summary_counts_match_findings(self):
        kex = self._make_kex(
            kex_algs=['diffie-hellman-group14-sha1', 'curve25519-sha256'],
            enc=['aes256-ctr'])
        evidence = build_evidence(None, None, kex)
        counts = summarize_evidence(evidence)
        assert counts[EvidenceType.NEGOTIATION_OBSERVATION] == 3
        assert counts[EvidenceType.BANNER_INFERENCE] == 0
        assert counts[EvidenceType.UNDETERMINED] == 0

    def test_build_struct_includes_evidence_with_legacy_fields_intact(self):
        kex = self._make_kex(enc=['aes128-cbc'])
        banner, software = self._parse('SSH-2.0-OpenSSH_7.2p1')
        struct = self.ssh_audit.build_struct(
            'localhost:22', banner, kex=kex, software=software)

        # New machine-readable evidence block is present.
        assert 'evidence' in struct
        assert struct['evidence']['fingerprint']['parsed']['product'] == \
            'OpenSSH'
        assert any(f['algorithm'] == 'aes128-cbc'
                   for f in struct['evidence']['findings'])

        # Legacy fields remain unchanged for backward compatibility.
        assert struct['cves'] == []
        assert struct['banner']['software'] == 'OpenSSH_7.2p1'
        legacy_enc = {e['algorithm']: e['notes'] for e in struct['enc']}
        assert 'warn' in legacy_enc['aes128-cbc']


# --- Offline banner/KEX combination matrix: text vs JSON consistency --------

OFFLINE_COMBOS = [
    # (banner, kex alg sets)
    ('SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1',
     {'kex': ['diffie-hellman-group14-sha1'],
      'key': ['ssh-rsa'], 'enc': ['aes128-cbc'], 'mac': ['hmac-sha1']}),
    ('SSH-2.0-OpenSSH_7.2-hpn14v5',
     {'kex': ['curve25519-sha256'], 'key': ['ssh-ed25519'],
      'enc': ['aes256-ctr'], 'mac': ['hmac-sha2-256-etm@openssh.com']}),
    ('SSH-2.0-WeirdSSH',
     {'kex': ['diffie-hellman-group1-sha1'], 'key': ['ssh-dss'],
      'enc': ['3des-cbc'], 'mac': ['hmac-md5']}),
    ('SSH-2.0-dropbear_2016.74',
     {'kex': ['diffie-hellman-group14-sha256'], 'key': ['ssh-rsa'],
      'enc': ['aes128-ctr'], 'mac': ['hmac-sha2-256']}),
]


@pytest.mark.parametrize('raw_banner,alg_sets', OFFLINE_COMBOS)
def test_offline_combos_text_matches_json(raw_banner, alg_sets):
    banner = Banner.parse(raw_banner)
    software = Software.parse(banner)
    kex = TestEvidence._make_kex(
        kex_algs=alg_sets['kex'], key_algs=alg_sets['key'],
        enc=alg_sets['enc'], mac=alg_sets['mac'])

    # JSON path: the same evidence structure embedded in build_struct().
    import ssh_audit.ssh_audit as ssh_audit_module
    struct = ssh_audit_module.build_struct(
        'localhost:22', banner, kex=kex, software=software)
    json_evidence = struct['evidence']
    text = '\n'.join(render_text_evidence(json_evidence))

    # 1. The inference status in JSON and text agree.
    status = json_evidence['fingerprint']['inference']['status']
    assert 'version evidence type: {}'.format(status) in text

    # 2. Every weak JSON finding is rendered with the same evidence type, and
    #    no weak finding is ever downgraded to an undetermined/banner result.
    weak_json = [f for f in json_evidence['findings']
                 if 'fail' in f['notes'] or 'warn' in f['notes']]
    assert len(weak_json) > 0
    for finding in weak_json:
        assert finding['type'] == EvidenceType.NEGOTIATION_OBSERVATION
        assert '({}) {}'.format(finding['algorithm_type'],
                                finding['algorithm']) in text
    assert EvidenceType.NEGOTIATION_OBSERVATION in text
    assert EvidenceType.UNDETERMINED not in text or status == \
        EvidenceType.UNDETERMINED

    # 3. The raw fingerprint survives unchanged in both representations.
    assert json_evidence['fingerprint']['raw_banner_software'] == \
        banner.software
    if banner.software is not None:
        assert banner.software in text

    # 4. No finding references notes that are absent from the bundled DB.
    db = SSH2_KexDB.get_db()
    for finding in json_evidence['findings']:
        entry = db[finding['algorithm_type']].get(finding['algorithm'])
        if entry is None:
            # GSS names are wildcard-normalized; everything else absent from
            # the DB must use only the canonical unknown-algorithm note.
            if not finding['algorithm'].startswith('gss-'):
                assert finding['notes'] == \
                    {'fail': [SSH2_KexDB.FAIL_UNKNOWN]}
