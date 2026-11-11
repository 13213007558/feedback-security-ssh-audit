"""
   The MIT License (MIT)

   Copyright (C) 2017-2025 Joe Testa (jtesta@positronsecurity.com)

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
"""
import struct
import traceback

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.banner import Banner
from ssh_audit.kexdh import KexDHException, KexGroupExchange, KexGroupExchange_SHA1, KexGroupExchange_SHA256
from ssh_audit.kexdh import KexGroupExchangeRejectException, KexGroupExchangeIncompleteException, KexGroupExchangeEncodingException, KexGroupExchangeRangeException
from ssh_audit.software import Software
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit import exitcodes


# Outcome of a single GEX request.  These strings are also used verbatim in
# the JSON report, so they form part of the output contract.
class GEXStatus:
    # A valid GEX group whose modulus lies within the requested range.
    SUCCESS = 'success'
    # The peer explicitly refused the request (SSH_MSG_DISCONNECT or another
    # terminal message).  This is not evidence about modulus sizes.
    REJECTED = 'rejected'
    # The connection was interrupted before the probe could complete.  This
    # is not evidence about modulus sizes.
    INCOMPLETE = 'incomplete'
    # The GEX group could not be decoded into a valid modulus/generator.
    ENCODING_ERROR = 'encoding_error'
    # A modulus was returned, but outside the requested min/max range.
    OUT_OF_RANGE = 'out_of_range'


# Everything we know about one GEX request and its answer.
class GEXAttempt:
    def __init__(self, min_bits: int, pref_bits: int, max_bits: int, status: str, observed_bits: Optional[int] = None, error: Optional[str] = None) -> None:
        self.min_bits = min_bits
        self.pref_bits = pref_bits
        self.max_bits = max_bits
        self.status = status
        # The actual group size returned by the peer.  Populated whenever a
        # modulus could be measured, including out-of-range answers.
        self.observed_bits = observed_bits
        self.error = error

    @property
    def request(self) -> Tuple[int, int, int]:
        return self.min_bits, self.pref_bits, self.max_bits

    @property
    def group_observed(self) -> bool:
        return self.observed_bits is not None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            'request': {'min': self.min_bits, 'pref': self.pref_bits, 'max': self.max_bits},
            'status': self.status,
        }
        if self.observed_bits is not None:
            d['observed_bits'] = self.observed_bits
        if self.error is not None:
            d['error'] = self.error
        return d


# The accumulated evidence for one group-exchange algorithm.  A single
# successful probe can never erase failed or uncompleted probes: every
# attempt is retained so downstream reports stay faithful to what was
# actually observed.
class GEXEvidence:
    # Moduli below this size are considered weak and fail the audit.
    WEAK_MODULUS_BITS = 2048

    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        self.attempts: List[GEXAttempt] = []

    def add(self, attempt: GEXAttempt) -> None:
        self.attempts.append(attempt)

    # Every modulus size actually returned by the peer (in-range or not).
    @property
    def observed_bits(self) -> List[int]:
        return sorted({a.observed_bits for a in self.attempts if a.observed_bits is not None})

    @property
    def smallest_observed_bits(self) -> Optional[int]:
        bits = self.observed_bits
        return bits[0] if len(bits) > 0 else None

    @property
    def weak_observed(self) -> bool:
        return any((a.observed_bits is not None) and (a.observed_bits < self.WEAK_MODULUS_BITS) for a in self.attempts)

    @property
    def has_encoding_errors(self) -> bool:
        return any(a.status == GEXStatus.ENCODING_ERROR for a in self.attempts)

    @property
    def has_out_of_range(self) -> bool:
        return any(a.status == GEXStatus.OUT_OF_RANGE for a in self.attempts)

    # True when at least one probe was refused or could not be completed.
    @property
    def has_unresolved_probes(self) -> bool:
        return any(a.status in (GEXStatus.REJECTED, GEXStatus.INCOMPLETE) for a in self.attempts)

    # True when no group was ever returned for this algorithm.  In that
    # situation nothing can be concluded about supported modulus sizes.
    @property
    def inconclusive(self) -> bool:
        return len(self.observed_bits) == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'algorithm': self.algorithm,
            'inconclusive': self.inconclusive,
            'weak_observed': self.weak_observed,
            'observed_bits': self.observed_bits,
            'attempts': [a.to_dict() for a in self.attempts],
        }


# Performs DH group exchanges to find what moduli are supported, and checks
# their size.
class GEXTest:

    # Registry of all evidence collected during the current process, keyed
    # by group-exchange algorithm name.  This is what text, JSON, and policy
    # reporting read from, ensuring all three express the same conclusion.
    evidence: Dict[str, GEXEvidence] = {}

    @staticmethod
    def reset_evidence() -> None:
        GEXTest.evidence = {}

    @staticmethod
    def get_evidence(algorithm: str) -> Optional[GEXEvidence]:
        return GEXTest.evidence.get(algorithm)

    @staticmethod
    def _record(algorithm: str, attempt: GEXAttempt) -> GEXEvidence:
        if algorithm not in GEXTest.evidence:
            GEXTest.evidence[algorithm] = GEXEvidence(algorithm)
        GEXTest.evidence[algorithm].add(attempt)
        return GEXTest.evidence[algorithm]

    # JSON-serializable view of all collected evidence, keyed by algorithm
    # name.  Sorting keys makes the output repeatable for testing.
    @staticmethod
    def evidence_struct() -> Dict[str, Any]:
        return {algorithm: GEXTest.evidence[algorithm].to_dict() for algorithm in sorted(GEXTest.evidence)}

    # Human-readable summary used by the granular (--gex-test) text output.
    # Each attempted request gets one line so successes and failures are
    # both visible.
    @staticmethod
    def write_text_summary(out: 'OutputBuffer') -> None:
        for algorithm in sorted(GEXTest.evidence):
            evidence = GEXTest.evidence[algorithm]
            for attempt in evidence.attempts:
                request_text = '%d:%d:%d' % (attempt.min_bits, attempt.pref_bits, attempt.max_bits)
                if attempt.group_observed:
                    line = '%s  %s --> %d-bit modulus (%s)' % (algorithm, request_text, attempt.observed_bits, attempt.status)
                else:
                    line = '%s  %s --> %s' % (algorithm, request_text, attempt.status)
                if attempt.status == GEXStatus.SUCCESS:
                    out.info(line)
                else:
                    out.warn(line)
            if evidence.inconclusive:
                out.warn('%s --> no GEX modulus could be obtained; supported modulus sizes could not be determined' % algorithm)


    # Creates a new connection to the server.  Returns True on success, or False.
    @staticmethod
    def reconnect(out: 'OutputBuffer', s: 'SSH_Socket', kex: 'SSH2_Kex', gex_alg: str) -> bool:
        if s.is_connected():
            return True

        err = s.connect()
        if err is not None:
            out.v(err, write_now=True)
            return False

        _, _, err = s.get_banner()
        if err is not None:
            out.v(err, write_now=True)
            s.close()
            return False

        # Send our KEX using the specified group-exchange and most of the
        # server's own values.
        s.send_kexinit(key_exchanges=[gex_alg], hostkeys=kex.key_algorithms, ciphers=kex.server.encryption, macs=kex.server.mac, compressions=kex.server.compression, languages=kex.server.languages)

        try:
            # Parse the server's KEX.
            _, payload = s.read_packet()
            SSH2_Kex.parse(out, payload)
        except (KexDHException, struct.error):
            out.v("Failed to parse server's kex.  Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)
            return False

        return True

    @staticmethod
    def granular_modulus_size_test(out: 'OutputBuffer', s: 'SSH_Socket', kex: 'SSH2_Kex', bits_min: int, bits_pref: int, bits_max: int, modulus_dict: Dict[str, List[int]]) -> int:
        '''
        Tests for granular modulus sizes.
        Builds a dictionary, where a key represents a DH algorithm name and the
        values are the modulus sizes (in bits) that have been returned by the
        target server.
        Returns an exitcodes.* flag.
        '''

        retval = exitcodes.GOOD

        out.d("Starting modulus_size_test...")
        out.d("Bits Min:  " + str(bits_min))
        out.d("Bits Pref: " + str(bits_pref))
        out.d("Bits Max:  " + str(bits_max))

        GEX_ALGS = {
            'diffie-hellman-group-exchange-sha1': KexGroupExchange_SHA1,
            'diffie-hellman-group-exchange-sha256': KexGroupExchange_SHA256,
        }

        # Check if the server supports any of the group-exchange
        # algorithms.  If so, test each one.
        for gex_alg, kex_group_class in GEX_ALGS.items():
            if gex_alg not in kex.kex_algorithms:
                out.d('Server does not support the algorithm "' + gex_alg + '".', write_now=True)
            else:
                kex_group = kex_group_class(out)
                out.d('Preparing to perform DH group exchange using ' + gex_alg + ' with min, pref and max modulus sizes of ' + str(bits_min) + ' bits, ' + str(bits_pref) + ' bits and ' + str(bits_max) + ' bits...', write_now=True)

                # It has been observed that reconnecting to some SSH servers
                # multiple times in quick succession can eventually result
                # in a "connection reset by peer" error. It may be possible
                # to recover from such an error by sleeping for some time
                # before continuing to issue reconnects.
                attempt = GEXTest._send_init(out, s, kex_group, kex, gex_alg, bits_min, bits_pref, bits_max)
                GEXTest._record(gex_alg, attempt)

                # Only a modulus that was actually observed is valid evidence
                # for modulus_dict.  A refusal, interrupted connection, or
                # unparseable message must never be represented as a size.
                if attempt.group_observed and attempt.observed_bits is not None:
                    if gex_alg in modulus_dict:
                        if attempt.observed_bits not in modulus_dict[gex_alg]:
                            modulus_dict[gex_alg].append(attempt.observed_bits)
                    else:
                        modulus_dict[gex_alg] = [attempt.observed_bits]

                alg_evidence = GEXTest.get_evidence(gex_alg)
                if alg_evidence is not None and alg_evidence.weak_observed:
                    # A weak modulus was actually observed: this is a
                    # definitive failure.
                    retval = exitcodes.FAILURE
                elif attempt.status != GEXStatus.SUCCESS:
                    # The probe was refused, interrupted, or the answer was
                    # malformed/out-of-range.  We lack conclusive evidence,
                    # so this is reported as a warning rather than silently
                    # treated as "only safe moduli are supported".
                    retval = max(retval, exitcodes.WARNING)

        return retval

    # Runs the DH moduli test against the specified target.
    @staticmethod
    def run(out: 'OutputBuffer', s: 'SSH_Socket', banner: Optional['Banner'], kex: 'SSH2_Kex') -> None:
        GEX_ALGS = {
            'diffie-hellman-group-exchange-sha1': KexGroupExchange_SHA1,
            'diffie-hellman-group-exchange-sha256': KexGroupExchange_SHA256,
        }

        GEXTest.reset_evidence()

        # The previous RSA tests put the server in a state we can't
        # test.  So we need a new connection to start with a clean
        # slate.
        if s.is_connected():
            s.close()

        # Check if the server supports any of the group-exchange
        # algorithms.  If so, test each one.
        for gex_alg, kex_group_class in GEX_ALGS.items():  # pylint: disable=too-many-nested-blocks
            if gex_alg in kex.kex_algorithms:
                out.d('Preparing to perform DH group exchange using ' + gex_alg + ' with min, pref and max modulus sizes of 512 bits, 1024 bits and 1536 bits...', write_now=True)

                kex_group = kex_group_class(out)
                first_attempt = GEXTest._send_init(out, s, kex_group, kex, gex_alg, 512, 1024, 1536)
                GEXTest._record(gex_alg, first_attempt)
                smallest_modulus = first_attempt.observed_bits if first_attempt.group_observed else -1

                # Try an array of specific modulus sizes... one at a time.
                for bits in [512, 768, 1024, 1536, 2048, 3072, 4096]:

                    # If we found one modulus size already, but we're about
                    # to test a larger one, don't bother.
                    if bits >= smallest_modulus > 0:
                        break

                    attempt = GEXTest._send_init(out, s, kex_group, kex, gex_alg, bits, bits, bits)
                    GEXTest._record(gex_alg, attempt)

                    # A refusal or interrupted connection does not establish a
                    # smallest modulus.  Keep probing the remaining sizes and
                    # preserve every outcome as evidence.
                    if attempt.group_observed and attempt.observed_bits is not None and (smallest_modulus <= 0 or attempt.observed_bits < smallest_modulus):
                        smallest_modulus = attempt.observed_bits

                # If the banner exists, then parse it into a Software object.  Next, if the target host is OpenSSH, check if its version is 9.9 or less; these versions are known to have a GEX fallback mechanism.
                software = None if banner is None else Software.parse(banner)
                is_openssh = False
                has_fallback_mechanism = False
                if (software is not None) and (software.product == "OpenSSH"):
                    is_openssh = True
                    try:
                        if float(software.version) <= 9.9:
                            has_fallback_mechanism = True
                            out.d(f"Found version of OpenSSH that includes GEX fallback mechanism: {software}")
                    except ValueError:
                        pass

                # If the smallest modulus is 2048 and the server is OpenSSH v9.9 or less, then we may have triggered the fallback mechanism, which tends to happen in testing scenarios such as this but not in most real-world conditions.  To better test this condition, we will do an additional check to see if the server supports sizes between 2048 and 4096, and consider this the definitive result only if it completes successfully.
                openssh_test_updated = False
                if (smallest_modulus == 2048) and is_openssh and has_fallback_mechanism:
                    out.d('First pass found a minimum GEX modulus of 2048 against OpenSSH server.  Performing a second pass to get a more accurate result...')
                    second_attempt = GEXTest._send_init(out, s, kex_group, kex, gex_alg, 2048, 3072, 4096)
                    out.d('Modulus size returned by server during second pass: %r' % second_attempt.observed_bits, write_now=True)
                    GEXTest._record(gex_alg, second_attempt)

                    # Only a completed second pass can refine the first-pass
                    # result.  A refusal or dropped connection leaves the
                    # original 2048-bit observation in place and keeps the
                    # evidence marked as incomplete.
                    if second_attempt.group_observed and second_attempt.observed_bits != 2048:
                        smallest_modulus = second_attempt.observed_bits
                        openssh_test_updated = True

                GEXTest._report(out, kex, gex_alg, smallest_modulus, openssh_test_updated)

    # Translates the collected GEX evidence into audit findings on the kex
    # object and the algorithm database.  Observations and missing evidence
    # are reported separately, so one successful probe can never mask a
    # probe that was refused or could not be completed.
    @staticmethod
    def _report(out: 'OutputBuffer', kex: 'SSH2_Kex', gex_alg: str, smallest_modulus: int, openssh_test_updated: bool) -> None:
        evidence = GEXTest.get_evidence(gex_alg)
        if evidence is None:
            return

        lst = SSH2_KexDB.get_db()['kex'][gex_alg]

        def add_note(level: int, text: str) -> None:
            while len(lst) <= level:
                lst.append([])
            if text not in lst[level]:
                lst[level].append(text)

        if smallest_modulus > 0:
            kex.set_dh_modulus_size(gex_alg, smallest_modulus)

            # We flag moduli smaller than 2048 as a failure.
            if smallest_modulus < 2048:
                text = 'using small %d-bit modulus' % smallest_modulus

                # For 'diffie-hellman-group-exchange-sha256', add
                # a failure reason.
                if len(lst) == 1:
                    lst.append([text])
                # For 'diffie-hellman-group-exchange-sha1', delete
                # the existing failure reason (which is vague), and
                # insert our own.
                else:
                    del lst[1]
                    lst.insert(1, [text])

            # Moduli smaller than 3072 get flagged as a warning.
            elif smallest_modulus < 3072:
                # Ensure this is only added once.
                text = '2048-bit modulus only provides 112-bits of symmetric strength'
                add_note(2, text)

        # Report every way in which evidence falls short.  These notes are
        # emitted even when at least one modulus was observed, so mixed
        # results retain both sides of the story.
        unresolved = sum(1 for a in evidence.attempts if a.status == GEXStatus.REJECTED)
        interrupted = sum(1 for a in evidence.attempts if a.status == GEXStatus.INCOMPLETE)
        if unresolved > 0:
            add_note(2, 'GEX request rejected by peer %d time(s); rejection does not prove that only safe modulus sizes are supported' % unresolved)
            out.warn('GEX request against %s was rejected %d time(s); no conclusion can be drawn about those modulus sizes.' % (gex_alg, unresolved))
        if interrupted > 0:
            add_note(2, 'GEX probe could not be completed %d time(s) due to connection errors; these sizes remain untested' % interrupted)
            out.warn('GEX probe against %s was interrupted %d time(s); those modulus sizes remain untested.' % (gex_alg, interrupted))
        if evidence.has_encoding_errors:
            count = sum(1 for a in evidence.attempts if a.status == GEXStatus.ENCODING_ERROR)
            add_note(1, 'peer returned %d illegally encoded GEX group response(s)' % count)
            out.fail('Peer returned %d illegally encoded GEX group response(s) for %s.' % (count, gex_alg))
        if evidence.has_out_of_range:
            for attempt in evidence.attempts:
                if attempt.status == GEXStatus.OUT_OF_RANGE:
                    add_note(1, 'GEX response of %d bits fell outside requested %d-%d bit range' % (attempt.observed_bits, attempt.min_bits, attempt.max_bits))
                    out.fail('GEX response of %d bits fell outside the requested %d-%d bit range for %s.' % (attempt.observed_bits, attempt.min_bits, attempt.max_bits, gex_alg))

        # If no group was ever returned, we have zero evidence about the
        # modulus sizes this algorithm supports.  This must not be presented
        # as a pass.
        if evidence.inconclusive:
            add_note(2, 'no GEX modulus could be obtained; supported modulus sizes could not be determined')
            out.warn('No GEX modulus could be obtained for %s; its supported modulus sizes could not be determined.' % gex_alg)
            reason = 'all %d GEX probe(s) were refused or could not be completed' % len(evidence.attempts)
            kex.set_gex_inconclusive(gex_alg, reason)

        # If we retested against OpenSSH (because its fallback mechanism was triggered), add a special note for the user.
        if openssh_test_updated:
            text = "OpenSSH's GEX fallback mechanism was triggered during testing. Very old SSH clients will still be able to create connections using a 2048-bit modulus, though modern clients will use %u. This can only be disabled by recompiling the code (see https://github.com/openssh/openssh-portable/blob/V_9_4/dh.c#L477)." % smallest_modulus
            add_note(3, text)

    @staticmethod
    def _send_init(out: 'OutputBuffer', s: 'SSH_Socket', kex_group: 'KexGroupExchange', kex: 'SSH2_Kex', gex_alg: str, min_bits: int, pref_bits: int, max_bits: int) -> 'GEXAttempt':
        '''Internal function for sending the GEX initialization to the server with the minimum, preferred, and maximum modulus bits.  Returns a GEXAttempt describing exactly what happened (success with the observed group size, explicit rejection, interrupted connection, malformed encoding, or an out-of-range answer).'''

        status = GEXStatus.INCOMPLETE
        observed_bits: Optional[int] = None
        error: Optional[str] = None
        try:
            if GEXTest.reconnect(out, s, kex, gex_alg) is False:
                status = GEXStatus.INCOMPLETE
                error = 'reconnection failed'
                out.d('GEXTest._send_init(%s, %u, %u, %u): reconnection failed.' % (gex_alg, min_bits, pref_bits, max_bits), write_now=True)
            else:
                kex_group.send_init_gex(s, min_bits, pref_bits, max_bits)

                # We have a group at this point (or a typed exception was
                # raised below).  Record its actual size before the rest of
                # the handshake, so a later interruption cannot erase the
                # evidence that this modulus was offered.
                observed_bits = kex_group.get_dh_modulus_size()
                try:
                    reply = kex_group.recv_reply(s, False)
                except KexDHException as e:
                    # The group itself was valid and observed; only the
                    # subsequent GEX_REPLY step failed.  Keep the modulus as
                    # evidence and mark the remainder of the probe
                    # incomplete.
                    status = GEXStatus.INCOMPLETE
                    error = 'GEX group received, but exchange could not be completed: %s' % str(e)
                    out.d('GEXTest._send_init(%s, %u, %u, %u): GEX_REPLY incomplete: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
                else:
                    if reply is None:
                        # The connection dropped during the GEX_REPLY step.
                        # The observed modulus remains valid evidence, but
                        # the probe as a whole could not be completed.
                        status = GEXStatus.INCOMPLETE
                        error = 'GEX group received, but connection was interrupted before GEX_REPLY'
                        out.d('GEXTest._send_init(%s, %u, %u, %u): connection interrupted before GEX_REPLY.' % (gex_alg, min_bits, pref_bits, max_bits), write_now=True)
                    else:
                        status = GEXStatus.SUCCESS
                        out.d('GEXTest._send_init(%s, %u, %u, %u): received modulus size: %d' % (gex_alg, min_bits, pref_bits, max_bits, observed_bits), write_now=True)
        except KexGroupExchangeRangeException as e:
            # The peer answered, but with a modulus outside the requested
            # bounds.  The measured size is still real evidence.
            status = GEXStatus.OUT_OF_RANGE
            observed_bits = e.observed_bits
            error = str(e)
            out.d('GEXTest._send_init(%s, %u, %u, %u): out-of-range modulus: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
        except KexGroupExchangeRejectException as e:
            status = GEXStatus.REJECTED
            error = str(e)
            out.d('GEXTest._send_init(%s, %u, %u, %u): request rejected: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
        except KexGroupExchangeEncodingException as e:
            status = GEXStatus.ENCODING_ERROR
            error = str(e)
            out.d('GEXTest._send_init(%s, %u, %u, %u): illegal GEX encoding: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
        except KexGroupExchangeIncompleteException as e:
            status = GEXStatus.INCOMPLETE
            error = str(e)
            out.d('GEXTest._send_init(%s, %u, %u, %u): probe incomplete: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
        except KexDHException as e:
            # Any other key-exchange failure means the probe could not be
            # completed; it is never interpreted as a refusal of weak moduli.
            status = GEXStatus.INCOMPLETE
            error = str(e)
            out.d('GEXTest._send_init(%s, %u, %u, %u): exception when performing DH group exchange init: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
        finally:
            s.close()

        return GEXAttempt(min_bits, pref_bits, max_bits, status, observed_bits, error)
