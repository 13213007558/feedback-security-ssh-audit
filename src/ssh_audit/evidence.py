"""
   The MIT License (MIT)

   Copyright (C) 2026 Joe Testa (jtesta@positronsecurity.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.

   Evidence classification for scan findings.

   The algorithm findings in this tool come from two fundamentally different
   kinds of input, and consumers must not treat them as equally conclusive:

     * A key exchange (KEXINIT) message is an actual negotiation observation.
       An algorithm advertised in that message was really offered by the peer,
       so a weak-algorithm finding against it is an observed fact.

     * The SSH banner is only a self-asserted, free-form software fingerprint.
       Anything derived from it (product/version parsing) is an inference.  It
       may carry a distribution suffix, a vendor re-branding, no usable version
       at all, or a version string whose upstream fixes were back-ported.

   This module only re-organizes data that already exists elsewhere in the
   repository (the banner, the parsed Software object, and the algorithm
   database).  It never introduces new vulnerability conclusions.
"""
import re

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.banner import Banner
from ssh_audit.software import Software
from ssh_audit.ssh2_kexdb import SSH2_KexDB


class EvidenceType:
    '''Machine-readable identifiers for the kind of evidence behind a claim.'''

    # The claim is directly supported by an observed key exchange message.
    NEGOTIATION_OBSERVATION = 'negotiation_observation'

    # The claim is inferred from parsing the self-asserted banner string.
    BANNER_INFERENCE = 'banner_inference'

    # The data needed to decide one way or the other was not available.
    UNDETERMINED = 'undetermined'

    ALL = (NEGOTIATION_OBSERVATION, BANNER_INFERENCE, UNDETERMINED)


# Maps the database slot indices used by SSH2_KexDB to their JSON/text labels.
_LEVEL_BY_SLOT = {1: 'fail', 2: 'warn', 3: 'info'}


def _db_entries_for(alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]],
                    alg_type: str,
                    algorithms: Sequence[str],
                    gss_normalize: bool
                    ) -> List[Tuple[str, List[List[Optional[str]]]]]:
    '''Returns (algorithm, raw database entry) pairs for advertised algorithms.

    GSS key exchange names carry variable base64 data and are stored in the
    database under wildcard names, so they are normalized before lookup (the
    same transformation output_algorithm() performs).
    '''
    ret: List[Tuple[str, List[List[Optional[str]]]]] = []
    for algorithm in algorithms:
        lookup_name = algorithm
        if gss_normalize and alg_type == 'kex' and \
                lookup_name.startswith('gss-'):
            last_dash = lookup_name.rindex('-')
            lookup_name = '{}-*'.format(lookup_name[0:last_dash])
        if lookup_name in alg_db[alg_type]:
            ret.append((algorithm, alg_db[alg_type][lookup_name]))
        else:
            # Unknown algorithms are still observed; their canonical note lives
            # outside the database and is added by the output layer.
            ret.append((algorithm, []))
    return ret


def _observed_notes(alg_desc: List[List[Optional[str]]]
                    ) -> Dict[str, List[str]]:
    '''Extracts the fail/warn/info note lists of a database entry.'''
    notes: Dict[str, List[str]] = {}
    for slot, level in _LEVEL_BY_SLOT.items():
        if len(alg_desc) > slot:
            messages = [msg for msg in alg_desc[slot] if msg is not None]
            if len(messages) > 0:
                notes[level] = messages
    return notes


def build_negotiation_findings(
        alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]],
        kex: Any) -> List[Dict[str, Any]]:
    '''Builds an evidence entry for every algorithm observed in the KEX message.

    The presence of the algorithm in the negotiated algorithm list is itself
    the observation.  All fail/warn/info notes attached to it in the bundled
    database therefore carry NEGOTIATION_OBSERVATION evidence, including weak
    algorithm problems: uncertainty about the banner must never downgrade them.
    '''
    findings: List[Dict[str, Any]] = []

    advertised: List[Tuple[str, Sequence[str]]] = [
        ('kex', kex.kex_algorithms),
        ('key', kex.key_algorithms),
        ('enc', kex.server.encryption),
        ('mac', kex.server.mac),
    ]

    for alg_type, algorithms in advertised:
        for algorithm, alg_desc in _db_entries_for(alg_db, alg_type,
                                                   algorithms, True):
            notes = _observed_notes(alg_desc)
            # Mirror build_struct(): an algorithm absent from the bundled
            # database is still an observed offer, and gets the same canonical
            # "unknown algorithm" note the legacy JSON uses.
            if len(notes) == 0 and algorithm not in alg_db[alg_type] and \
                    not (alg_type == 'kex' and algorithm.startswith('gss-')):
                notes = {'fail': [SSH2_KexDB.FAIL_UNKNOWN]}
            findings.append({
                'type': EvidenceType.NEGOTIATION_OBSERVATION,
                'algorithm_type': alg_type,
                'algorithm': algorithm,
                'notes': notes,
                'basis': 'algorithm advertised in the peer key exchange '
                         '(KEXINIT) message; notes are from the bundled '
                         'algorithm database',
            })
    return findings


def _version_inference(software: Optional[Software],
                       banner: Optional[Banner]) -> Dict[str, Any]:
    '''Classifies how trustworthy the banner-derived version information is.

    A banner is always a self-asserted fingerprint, so a successfully parsed
    product/version is at best a BANNER_INFERENCE.  Additional caveats record
    the situations that make version-based vulnerability conclusions
    unreliable: repackaged builds, vendor re-brandings, missing versions, and
    version strings whose upstream fixes may have been back-ported.
    '''
    if software is None:
        return {
            'status': EvidenceType.UNDETERMINED,
            'reasons': ['banner software string could not be parsed into a '
                        'known product and version'],
        }

    reasons: List[str] = []
    if not bool(software.version):
        reasons.append('no numeric version could be parsed from the banner')

    # A portable OpenSSH 'pN' suffix (e.g. '8.4p1') is the upstream release
    # naming, not a distribution modification.  Any other patch suffix is a
    # non-upstream build that may carry back-ported fixes.
    patch = software.patch or ''
    if bool(patch) and not re.match(r'^p\d+$', patch):
        reasons.append('non-upstream patch/vendor suffix in version string: '
                       '{!r}; fixes may have been back-ported'.format(patch))

    if bool(software.os):
        reasons.append('banner identifies a repackaged/OS build ({!r}); '
                       'distributors commonly back-port patches without '
                       'changing the upstream version number'
                       .format(software.os))

    if banner is not None and bool(banner.comments) and not bool(software.os):
        reasons.append('banner carries free-form comments {!r} which may '
                       'indicate a vendor re-branding or repackaged build'
                       .format(banner.comments))

    if len(reasons) == 0:
        reasons.append('product and version parsed from the self-asserted '
                       'banner string; not independently verified')

    return {'status': EvidenceType.BANNER_INFERENCE, 'reasons': reasons}


def build_fingerprint(banner: Optional[Banner],
                      software: Optional[Software]) -> Dict[str, Any]:
    '''Preserves the raw software fingerprint and its parsed interpretation.

    No field here is dropped: the original banner software string, the parsed
    product/version/patch/OS components, and the parse caveats are all retained
    so downstream callers can make their own judgement.
    '''
    raw_software = None
    raw_comments = None
    if banner is not None:
        raw_software = banner.software
        raw_comments = banner.comments

    parsed: Optional[Dict[str, Any]] = None
    if software is not None:
        parsed = {
            'vendor': software.vendor,
            'product': software.product,
            'version': software.version if bool(software.version) else None,
            'patch': software.patch,
            'os': software.os,
            'display': software.display(),
        }

    inference = _version_inference(software, banner)
    return {
        'raw_banner_software': raw_software,
        'raw_banner_comments': raw_comments,
        'parsed': parsed,
        'inference': inference,
    }


def build_evidence(banner: Optional[Banner],
                   software: Optional[Software],
                   kex: Optional[Any],
                   alg_db: Optional[Dict[str, Dict[str,
                                            List[List[Optional[str]]]]]] = None
                   ) -> Dict[str, Any]:
    '''Assembles the full, machine-readable evidence section.

    This is a pure re-organization of existing inputs; it does not fetch data
    from any other source and does not add vulnerability claims that the
    bundled database does not already contain.
    '''
    if alg_db is None:
        alg_db = SSH2_KexDB.get_db()

    findings: List[Dict[str, Any]] = []
    if kex is not None:
        findings = build_negotiation_findings(alg_db, kex)

    return {
        'fingerprint': build_fingerprint(banner, software),
        'findings': findings,
        'evidence_types': list(EvidenceType.ALL),
    }


def summarize_evidence(evidence: Dict[str, Any]) -> Dict[str, int]:
    '''Counts findings per evidence type (handy for text output and tests).'''
    counts = {evidence_type: 0 for evidence_type in EvidenceType.ALL}
    for finding in evidence.get('findings', []):
        evidence_type = finding.get('type')
        if evidence_type in counts:
            counts[evidence_type] += 1
    return counts


# Short, human-readable labels used in the text report.  The machine-readable
# identifiers above remain the stable contract for automated consumers.
_TEXT_LABELS = {
    EvidenceType.NEGOTIATION_OBSERVATION: 'negotiation observation',
    EvidenceType.BANNER_INFERENCE: 'banner inference',
    EvidenceType.UNDETERMINED: 'undetermined',
}


def render_text_evidence(evidence: Dict[str, Any]) -> List[str]:
    '''Renders the evidence section as plain text lines (no colors/ANSI).

    The text report and the JSON report are built from the same evidence
    structure, so they cannot express different conclusions.
    '''
    lines: List[str] = []
    fingerprint = evidence.get('fingerprint', {})
    inference = fingerprint.get('inference', {})
    parsed = fingerprint.get('parsed')

    raw_software = fingerprint.get('raw_banner_software')
    lines.append('(evd) fingerprint source: banner string {!r}'
                 .format(raw_software))
    if parsed is not None:
        lines.append('(evd) parsed fingerprint: {}'.format(
            parsed.get('display')))
    else:
        lines.append('(evd) parsed fingerprint: none')

    inference_status = inference.get('status', EvidenceType.UNDETERMINED)
    lines.append('(evd) version evidence type: {} ({})'.format(
        inference_status, _TEXT_LABELS.get(inference_status,
                                           inference_status)))
    for reason in inference.get('reasons', []):
        lines.append('(evd) `- {}'.format(reason))

    counts = summarize_evidence(evidence)
    observed = counts.get(EvidenceType.NEGOTIATION_OBSERVATION, 0)
    lines.append('(evd) negotiated algorithm findings: {} (all are direct '
                 'observations, never banner guesses)'.format(observed))

    weak_findings = []
    for finding in evidence.get('findings', []):
        notes = finding.get('notes', {})
        if 'fail' in notes or 'warn' in notes:
            weak_findings.append(finding)

    for finding in weak_findings:
        levels = []
        for level in ('fail', 'warn'):
            for _ in finding.get('notes', {}).get(level, []):
                levels.append(level)
        lines.append('(evd) ({}) {} -- [{}] {}'.format(
            finding.get('algorithm_type'),
            finding.get('algorithm'),
            EvidenceType.NEGOTIATION_OBSERVATION,
            ', '.join(levels)))

    return lines
