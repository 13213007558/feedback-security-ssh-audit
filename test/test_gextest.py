"""
Tests for the DH group-exchange (GEX) probe and its reporting.

Every test drives GEXTest with a fake socket (the virtual_socket fixture)
and small, hand-built SSH message samples.  No real server is contacted and
no load is generated against any network target.
"""
import copy
import json
import socket
import struct

import pytest

from ssh_audit import exitcodes
from ssh_audit.auditconf import AuditConf
from ssh_audit.gextest import GEXTest, GEXStatus, GEXAttempt
from ssh_audit.kexdh import KexGroupExchange_SHA1, KexGroupExchange_SHA256
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.protocol import Protocol
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.writebuf import WriteBuf


GEX_SHA256 = 'diffie-hellman-group-exchange-sha256'
GEX_SHA1 = 'diffie-hellman-group-exchange-sha1'
GEX_ALGS = [GEX_SHA256, GEX_SHA1]


def _frame(payload_body):
    """Wraps an SSH payload (including its leading message-type byte) in a
    complete binary SSH packet."""
    padding = -(len(payload_body) + 5) % 8
    if padding < 4:
        padding += 8
    plen = len(payload_body) + padding + 1
    return struct.pack('>Ib', plen, padding) + payload_body + b'\x00' * padding


def _prime_bytes(bits):
    """A deterministic prime-sized sample (all 0xff) of exactly bits bits."""
    return ((1 << bits) - 1).to_bytes((bits + 7) // 8, 'big')


def _kexinit_payload(kex_algs):
    w = WriteBuf()
    w.write(b'\x00' * 16)
    w.write_list(kex_algs)
    w.write_list(['ssh-rsa'])
    party = ['aes128-ctr']
    mac = ['hmac-sha1']
    comp = ['none']
    lang = ['']
    w.write_list(party)
    w.write_list(party)
    w.write_list(mac)
    w.write_list(mac)
    w.write_list(comp)
    w.write_list(comp)
    w.write_list(lang)
    w.write_list(lang)
    w.write_byte(False)
    w.write_int(0)
    return w.write_flush()


def _kexinit_packet(kex_algs):
    return _frame(bytes([Protocol.MSG_KEXINIT]) + _kexinit_payload(kex_algs))


def _gex_group_packet(p_bytes, g_bytes=b'\x02'):
    w = WriteBuf()
    w.write_byte(Protocol.MSG_KEXDH_GEX_GROUP)
    w.write_string(p_bytes)
    w.write_string(g_bytes)
    return _frame(w.write_flush())


def _gex_reply_packet():
    w = WriteBuf()
    w.write_byte(Protocol.MSG_KEXDH_GEX_REPLY)
    w.write_string(b'\x00\x00\x00\x07ssh-rsa')  # Host key blob.
    w.write_string(b'\x01')                      # F.
    w.write_string(b'\x02')                      # Signature.
    return _frame(w.write_flush())


def _disconnect_packet():
    w = WriteBuf()
    w.write_byte(Protocol.MSG_DISCONNECT)
    w.write_int(11)                 # SSH_DISCONNECT_BY_APPLICATION.
    w.write_string(b'no acceptable groups')
    w.write_string(b'en')
    return _frame(w.write_flush())


def _terminal_packet(message_type):
    """Any non-GEX_GROUP terminal message, e.g. SSH_MSG_NEWKEYS."""
    return _frame(bytes([message_type]))


def _truncated_group_packet(declared_len, actual):
    w = WriteBuf()
    w.write_byte(Protocol.MSG_KEXDH_GEX_GROUP)
    w.write_int(declared_len)
    w.write(actual)
    return _frame(w.write_flush())


def _zero_length_modulus_packet():
    w = WriteBuf()
    w.write_byte(Protocol.MSG_KEXDH_GEX_GROUP)
    w.write_string(b'')
    w.write_string(b'\x02')
    return _frame(w.write_flush())


class _ConnectionSocket:
    """A per-connection view of the virtual socket.

    It owns its own receive queue, so an EOF on one connection cannot drain
    data scripted for a later reconnect (which is how a real socket behaves).
    Writes and every other attribute are delegated to the underlying virtual
    socket.
    """

    def __init__(self, vsocket, rdata):
        self._vsocket = vsocket
        self._rdata = rdata
        self._closed = False

    def recv(self, bufsize, flags=0):
        # pylint: disable=unused-argument
        if self._closed or not self._rdata:
            return b''
        data = self._rdata.pop(0)
        if isinstance(data, Exception):
            raise data
        return data

    def close(self):
        self._closed = True
        return self._vsocket.close()

    def shutdown(self, how):
        self._closed = True
        return self._vsocket.shutdown(how)

    def __getattr__(self, name):
        return getattr(self._vsocket, name)


class FakeGEXServer:
    """A behavior-driven fake SSH server using only in-memory sockets.

    Test code registers a response script per group-exchange algorithm.
    Each entry describes how the next GEX request on a fresh connection is
    answered ('group', 'disconnect', 'drop', 'terminal', or an encoding
    error).  The algorithm in effect for a connection is taken from the
    KEXINIT the client sends, so multiple algorithms can be scripted
    independently even though they share one virtual socket.

    No real network I/O is performed.
    """

    def __init__(self, vsocket, kex_algs, monkeypatch):
        self.vsocket = vsocket
        self.kex_algs = kex_algs
        self.requests_seen = []  # (min, pref, max) tuples parsed from the wire.
        # Per-algorithm list of scripts; each entry is a dict describing
        # the answer for the next connection using that algorithm.
        self._scripts = {alg: [] for alg in kex_algs}
        self._active = None
        self._active_alg = None
        monkeypatch.setattr(socket, 'socket', self._socket_factory)
        monkeypatch.setattr(socket, 'create_connection', self._create_connection)

    # --- script registration -------------------------------------------------

    def _add(self, algorithm, script):
        self._scripts.setdefault(algorithm, []).append(script)

    def queue_group(self, modulus_bits, in_range_reply=True, g_bytes=b'\x02', algorithm=None):
        algorithm = algorithm or self.kex_algs[0]
        self._add(algorithm, {'kind': 'group', 'bits': modulus_bits,
                              'reply': in_range_reply, 'g': g_bytes})

    def queue_disconnect(self, algorithm=None):
        algorithm = algorithm or self.kex_algs[0]
        self._add(algorithm, {'kind': 'disconnect'})

    def queue_terminal(self, message_type=21, algorithm=None):
        algorithm = algorithm or self.kex_algs[0]
        self._add(algorithm, {'kind': 'terminal', 'message_type': message_type})

    def queue_connection_drop(self, algorithm=None):
        algorithm = algorithm or self.kex_algs[0]
        self._add(algorithm, {'kind': 'drop'})

    def queue_illegal_encoding(self, mode='zero_length', algorithm=None):
        algorithm = algorithm or self.kex_algs[0]
        self._add(algorithm, {'kind': 'encoding', 'mode': mode})

    def queue_raw_packet(self, packet, algorithm=None):
        """Serves an arbitrary pre-built packet as the GEX answer."""
        algorithm = algorithm or self.kex_algs[0]
        self._add(algorithm, {'kind': 'raw', 'packet': packet})

    # --- socket plumbing -----------------------------------------------------

    def _socket_factory(self, *args, **kwargs):
        return self

    def _create_connection(self, address, timeout=0, source_address=None):
        # pylint: disable=unused-argument
        return self

    def connect(self, address):
        # A new connection serves its banner immediately; the GEX answer is
        # materialized later once the client's KEXINIT names the algorithm.
        self._active = _ConnectionSocket(self.vsocket, [b'SSH-2.0-FakeGEX\r\n'])
        self._active_alg = None
        self._script_materialized = False
        return None

    def connect_ex(self, address):
        return self.connect(address)

    def settimeout(self, timeout):
        return self.vsocket.settimeout(timeout)

    def setsockopt(self, *args):
        return None

    def fileno(self):
        return self.vsocket.fileno()

    def _detect_algorithm(self, kexinit_packet):
        # Parse the key-exchange name-list out of the KEXINIT payload rather
        # than doing a substring match (the SHA256 algorithm name contains
        # 'sha1' as a prefix, so naive matching would misroute).
        idx = kexinit_packet.find(bytes([Protocol.MSG_KEXINIT]))
        if idx == -1:
            return self.kex_algs[0]
        ptr = idx + 1 + 16  # Skip message type and 16-byte cookie.
        if ptr + 4 > len(kexinit_packet):
            return self.kex_algs[0]
        name_len = struct.unpack('>I', kexinit_packet[ptr:ptr + 4])[0]
        ptr += 4
        names = kexinit_packet[ptr:ptr + name_len].decode('utf-8', 'replace').split(',')
        for alg in self._scripts:
            if alg in names:
                return alg
        return self.kex_algs[0]

    def _materialize_script(self, algorithm):
        # The banner was already queued at connect(); append the KEXINIT and
        # the scripted GEX answer for this algorithm.
        queue = self._active._rdata
        queue.append(_kexinit_packet([algorithm]))
        scripts = self._scripts.get(algorithm, [])
        script = scripts.pop(0) if scripts else {'kind': 'drop'}
        kind = script['kind']
        if kind == 'group':
            queue.append(_gex_group_packet(_prime_bytes(script['bits']), script['g']))
            if script['reply']:
                queue.append(_gex_reply_packet())
        elif kind == 'disconnect':
            queue.append(_disconnect_packet())
        elif kind == 'terminal':
            queue.append(_terminal_packet(script['message_type']))
        elif kind == 'encoding':
            if script['mode'] == 'zero_length':
                queue.append(_zero_length_modulus_packet())
            else:
                queue.append(_truncated_group_packet(64, b'\x01\x02'))
        elif kind == 'raw':
            queue.append(script['packet'])
        # 'drop' adds nothing beyond the KEXINIT, yielding EOF afterwards.

    def recv(self, bufsize, flags=0):
        # pylint: disable=unused-argument
        if self._active is None:
            return b''
        # Once the algorithm is known, materialize this connection's answer
        # the first time its queue runs dry after the banner.
        if self._active_alg is not None and not self._script_materialized:
            self._materialize_script(self._active_alg)
            self._script_materialized = True
        return self._active.recv(bufsize, flags)

    def send(self, data):
        # Record writes on the shared virtual socket's sink directly; the
        # underlying object itself never performs a connect() in this setup.
        self.vsocket.sdata.append(data)
        # The KEXINIT packet (framed payload starts with message type 20)
        # names the negotiated group-exchange algorithm.  Distinguish it from
        # the later GEX_INIT (type 32), which merely shares an incidental byte
        # elsewhere in its framing, by validating the parsed name-list.
        if (self._active_alg is None) and data and self._is_kexinit_packet(data):
            candidate = self._detect_algorithm(data)
            if candidate in self._scripts:
                self._active_alg = candidate

    def _is_kexinit_packet(self, data):
        idx = data.find(bytes([Protocol.MSG_KEXINIT]))
        if idx == -1:
            return False
        ptr = idx + 1 + 16  # Skip message type and 16-byte cookie.
        if ptr + 4 > len(data):
            return False
        name_len = struct.unpack('>I', data[ptr:ptr + 4])[0]
        if name_len == 0 or ptr + 4 + name_len > len(data):
            return False
        names = data[ptr + 4:ptr + 4 + name_len].decode('utf-8', 'replace').split(',')
        # A KEXINIT carries every negotiated algorithm family, not just kex.
        # The GEX_INIT message never contains a name-list that matches one of
        # our group-exchange algorithms, so this is unambiguous in practice.
        return any(alg in names for alg in self._scripts)

    def sendall(self, data):
        self.vsocket.sdata.append(data)

    def close(self):
        if self._active is not None:
            self._active._closed = True

    def shutdown(self, how):
        if self._active is not None:
            self._active._closed = True

    def getpeername(self):
        return self.vsocket.getpeername()

    def getsockname(self):
        return self.vsocket.getsockname()

    def capture_requests(self):
        """Extracts the (min, pref, max) triple of every GEX request sent."""
        for raw in self.vsocket.sdata:
            idx = raw.find(bytes([Protocol.MSG_KEXDH_GEX_REQUEST]))
            if idx == -1:
                continue
            body = raw[idx + 1:]
            self.requests_seen.append(struct.unpack('>III', body[:12]))
        return self.requests_seen


# pylint: disable=attribute-defined-outside-init
class TestGEXProbe:
    @pytest.fixture(autouse=True)
    def init(self, virtual_socket, monkeypatch):
        self.vsocket = virtual_socket
        self.monkeypatch = monkeypatch
        self.out = OutputBuffer()
        GEXTest.reset_evidence()
        self._db_snapshot = copy.deepcopy(SSH2_KexDB.get_db())
        yield
        # Restore the entire shared algorithm database (kex/key/enc/mac)
        # so per-test notes never leak into other test modules.
        SSH2_KexDB.get_db().clear()
        SSH2_KexDB.get_db().update(copy.deepcopy(self._db_snapshot))

    def _socket(self):
        return SSH_Socket(self.out, 'localhost', 22)

    def _kex(self, kex_algs=None):
        kex_algs = GEX_ALGS if kex_algs is None else kex_algs
        party = SSH2_KexParty(['aes128-ctr'], ['hmac-sha1'], ['none'], [''])
        return SSH2_Kex(self.out, b'\x00' * 16, kex_algs, ['ssh-rsa'], party, party, False)

    def _send(self, server, algorithm, min_bits, pref_bits, max_bits):
        klass = KexGroupExchange_SHA256 if algorithm == GEX_SHA256 else KexGroupExchange_SHA1
        attempt = GEXTest._send_init(self.out, self._socket(), klass(self.out), self._kex([algorithm]),
                                     algorithm, min_bits, pref_bits, max_bits)
        GEXTest._record(algorithm, attempt)
        return attempt

    def test_success_records_actual_group_size(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.SUCCESS
        assert attempt.observed_bits == 1024
        assert attempt.request == (512, 1024, 1536)
        assert server.capture_requests() == [(512, 1024, 1536)]

    def test_explicit_disconnect_is_rejection_not_safe_modulus(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_disconnect()
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.REJECTED
        assert attempt.observed_bits is None
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence is not None and evidence.inconclusive is True
        # No modulus must ever be recorded from a rejection.
        assert evidence.observed_bits == []

    def test_terminal_message_is_rejection(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_terminal(Protocol.MSG_NEWKEYS)
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.REJECTED
        assert attempt.observed_bits is None

    def test_connection_drop_is_incomplete_not_rejection_or_pass(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_connection_drop()
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.INCOMPLETE
        assert attempt.observed_bits is None
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.inconclusive is True

    def test_out_of_range_response_keeps_observed_size(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        # Request a 2048-only range, but the peer answers with a 1024 group.
        server.queue_group(1024, in_range_reply=False)
        attempt = self._send(server, GEX_SHA256, 2048, 2048, 2048)
        assert attempt.status == GEXStatus.OUT_OF_RANGE
        assert attempt.observed_bits == 1024
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.observed_bits == [1024]
        assert evidence.has_out_of_range is True

    def test_illegal_zero_length_modulus_is_encoding_error(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_illegal_encoding('zero_length')
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.ENCODING_ERROR
        assert attempt.observed_bits is None

    def test_truncated_modulus_encoding_is_encoding_error(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_illegal_encoding('truncated')
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.ENCODING_ERROR
        assert attempt.observed_bits is None

    def test_oversized_declared_length_is_encoding_error(self):
        # A length field claiming far more bytes than exist must be rejected
        # as an encoding error rather than raising an uncaught IndexError.
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        malformed = _truncated_group_packet(0x7fffffff, b'\x01\x02')
        server.queue_raw_packet(malformed)
        attempt = self._send(server, GEX_SHA256, 512, 1024, 1536)
        assert attempt.status == GEXStatus.ENCODING_ERROR
        assert attempt.observed_bits is None

    def test_group_then_dropped_reply_keeps_evidence(self):
        # A group is delivered, but the connection dies before GEX_REPLY.
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(2048, in_range_reply=False)
        attempt = self._send(server, GEX_SHA256, 2048, 2048, 2048)
        assert attempt.status == GEXStatus.INCOMPLETE
        assert attempt.observed_bits == 2048
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.observed_bits == [2048]
        assert evidence.inconclusive is False


# pylint: disable=attribute-defined-outside-init
class TestGEXRunReporting:
    @pytest.fixture(autouse=True)
    def init(self, virtual_socket, monkeypatch):
        self.vsocket = virtual_socket
        self.monkeypatch = monkeypatch
        self.out = OutputBuffer()
        GEXTest.reset_evidence()
        self._db_snapshot = copy.deepcopy(SSH2_KexDB.get_db())
        yield
        SSH2_KexDB.get_db().clear()
        SSH2_KexDB.get_db().update(copy.deepcopy(self._db_snapshot))

    def _kex(self, kex_algs=None):
        kex_algs = GEX_ALGS if kex_algs is None else kex_algs
        party = SSH2_KexParty(['aes128-ctr'], ['hmac-sha1'], ['none'], [''])
        return SSH2_Kex(self.out, b'\x00' * 16, kex_algs, ['ssh-rsa'], party, party, False)

    def _run(self, server, kex, banner=None):
        sock = SSH_Socket(self.out, 'localhost', 22)
        GEXTest.run(self.out, sock, banner, kex)
        return kex

    def _db_notes(self, algorithm):
        return SSH2_KexDB.get_db()['kex'][algorithm]

    def test_weak_group_observed_is_reported_as_failure(self):
        # The initial (512:1024:1536) probe returns a 1024-bit group.  The
        # 512 and 768 specific-size probes still run (both below 1024), then
        # the loop breaks at the 1024 boundary.  The observed weak modulus is
        # recorded as a failure regardless of those later probes.
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)
        kex = self._run(server, self._kex([GEX_SHA256]))
        assert kex.dh_modulus_sizes() == {GEX_SHA256: 1024}
        fail_notes = self._db_notes(GEX_SHA256)[1]
        assert any('using small 1024-bit modulus' in n for n in fail_notes)
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.weak_observed is True
        assert evidence.inconclusive is False

    def test_all_rejections_never_imply_safe_moduli(self):
        # Every probe the run performs is explicitly rejected.
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        for _ in range(8):  # 1 initial + 7 specific-size probes.
            server.queue_disconnect()
        kex = self._run(server, self._kex([GEX_SHA256]))
        # No modulus size may be set, since nothing was ever observed.
        assert kex.dh_modulus_sizes() == {}
        assert GEX_SHA256 in kex.gex_inconclusive()
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.inconclusive is True
        assert all(a.status == GEXStatus.REJECTED for a in evidence.attempts)
        warn_notes = self._db_notes(GEX_SHA256)[2]
        assert any('rejected by peer' in n for n in warn_notes)
        assert any('could not be determined' in n for n in warn_notes)

    def test_all_connection_drops_are_inconclusive(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        for _ in range(8):
            server.queue_connection_drop()
        kex = self._run(server, self._kex([GEX_SHA256]))
        assert kex.dh_modulus_sizes() == {}
        assert GEX_SHA256 in kex.gex_inconclusive()
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert all(a.status == GEXStatus.INCOMPLETE for a in evidence.attempts)
        warn_notes = self._db_notes(GEX_SHA256)[2]
        assert any('connection errors' in n for n in warn_notes)

    def test_mixed_success_and_failure_retains_both_sides(self):
        # First probe succeeds with a strong 3072-bit group; the run then
        # skips the specific-size probes, so add a single success plus one
        # explicit rejection recorded through the granular path to exercise
        # mixed evidence retention within one algorithm.
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(3072)
        kex = self._run(server, self._kex([GEX_SHA256]))
        assert kex.dh_modulus_sizes() == {GEX_SHA256: 3072}

        # A later, separate probe on the same algorithm is rejected; the
        # earlier successful observation must survive.
        server.queue_disconnect()
        reject = GEXTest._send_init(self.out, SSH_Socket(self.out, 'localhost', 22),
                                    KexGroupExchange_SHA256(self.out), self._kex([GEX_SHA256]),
                                    GEX_SHA256, 512, 512, 512)
        GEXTest._record(GEX_SHA256, reject)
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.observed_bits == [3072]
        assert any(a.status == GEXStatus.REJECTED for a in evidence.attempts)
        assert evidence.inconclusive is False  # A group was observed.
        assert evidence.has_unresolved_probes is True

    def test_out_of_range_and_encoding_errors_become_fail_notes(self):
        # The initial request is 512:1024:1536, but the peer answers with a
        # 2048-bit group (out of range).  run() records the observed 2048
        # size, then probes 512/768/1024/1536; each answer is an illegal
        # encoding before the loop breaks at the 2048 boundary.
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(2048, in_range_reply=False)
        for _ in range(4):
            server.queue_illegal_encoding('zero_length')
        kex = self._run(server, self._kex([GEX_SHA256]))
        evidence = GEXTest.get_evidence(GEX_SHA256)
        assert evidence.has_out_of_range is True
        assert evidence.has_encoding_errors is True
        assert evidence.observed_bits == [2048]
        fail_notes = self._db_notes(GEX_SHA256)[1]
        assert any('outside requested' in n for n in fail_notes)
        assert any('illegally encoded' in n for n in fail_notes)
        # The observed modulus is still recorded as evidence.
        assert kex.dh_modulus_sizes() == {GEX_SHA256: 2048}

    def test_request_triples_are_distinguished_in_evidence(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)  # Initial (512, 1024, 1536) request.
        self._run(server, self._kex([GEX_SHA256]))
        triples = [a.request for a in GEXTest.get_evidence(GEX_SHA256).attempts]
        assert (512, 1024, 1536) in triples
        assert all(isinstance(t, tuple) and len(t) == 3 for t in triples)

    def test_sha1_weak_group_replaces_vague_failure_note(self):
        # The SHA1 GEX algorithm ships with a generic SHA-1 failure note;
        # a weak observed modulus must replace it with the specific reason.
        server = FakeGEXServer(self.vsocket, [GEX_SHA1], self.monkeypatch)
        server.queue_group(1024)
        kex = self._run(server, self._kex([GEX_SHA1]))
        assert kex.dh_modulus_sizes() == {GEX_SHA1: 1024}
        fail_notes = self._db_notes(GEX_SHA1)[1]
        assert any('using small 1024-bit modulus' in n for n in fail_notes)
        assert not any('broken SHA-1' in n for n in fail_notes)

    def test_both_gex_algorithms_are_tested_independently(self):
        # Script each algorithm independently: SHA256 offers a weak group on
        # its first connection, while SHA1 refuses every probe it makes.
        server = FakeGEXServer(self.vsocket, GEX_ALGS, self.monkeypatch)
        server.queue_group(1024, algorithm=GEX_SHA256)
        for _ in range(8):
            server.queue_disconnect(algorithm=GEX_SHA1)
        kex = self._run(server, self._kex(GEX_ALGS))
        # Only SHA256 ever observed a modulus; SHA1's probes were all
        # refused and must remain inconclusive.
        assert kex.dh_modulus_sizes() == {GEX_SHA256: 1024}
        assert GEX_SHA1 in kex.gex_inconclusive()
        sha256_evidence = GEXTest.get_evidence(GEX_SHA256)
        sha1_evidence = GEXTest.get_evidence(GEX_SHA1)
        assert sha256_evidence.weak_observed is True
        assert sha1_evidence.inconclusive is True
        assert all(a.status == GEXStatus.REJECTED for a in sha1_evidence.attempts)


# pylint: disable=attribute-defined-outside-init
class TestGEXGranularAndOutputs:
    @pytest.fixture(autouse=True)
    def init(self, virtual_socket, monkeypatch):
        self.vsocket = virtual_socket
        self.monkeypatch = monkeypatch
        self.out = OutputBuffer()
        GEXTest.reset_evidence()
        self._db_snapshot = copy.deepcopy(SSH2_KexDB.get_db())
        yield
        SSH2_KexDB.get_db().clear()
        SSH2_KexDB.get_db().update(copy.deepcopy(self._db_snapshot))

    def _kex(self, kex_algs=None):
        kex_algs = GEX_ALGS if kex_algs is None else kex_algs
        party = SSH2_KexParty(['aes128-ctr'], ['hmac-sha1'], ['none'], [''])
        return SSH2_Kex(self.out, b'\x00' * 16, kex_algs, ['ssh-rsa'], party, party, False)

    def test_granular_weak_observation_returns_failure(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)
        mod_dict = {}
        rc = GEXTest.granular_modulus_size_test(self.out, self._socket_like(), self._kex([GEX_SHA256]),
                                                1024, 1024, 1024, mod_dict)
        assert rc == exitcodes.FAILURE
        assert mod_dict == {GEX_SHA256: [1024]}

    def test_granular_rejection_returns_warning_not_good(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_disconnect()
        mod_dict = {}
        rc = GEXTest.granular_modulus_size_test(self.out, self._socket_like(), self._kex([GEX_SHA256]),
                                                1024, 1024, 1024, mod_dict)
        assert rc == exitcodes.WARNING
        assert mod_dict == {}  # A rejection never fabricates a modulus size.

    def test_granular_connection_drop_returns_warning(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_connection_drop()
        mod_dict = {}
        rc = GEXTest.granular_modulus_size_test(self.out, self._socket_like(), self._kex([GEX_SHA256]),
                                                2048, 2048, 2048, mod_dict)
        assert rc == exitcodes.WARNING
        assert mod_dict == {}

    def _socket_like(self):
        return SSH_Socket(self.out, 'localhost', 22)

    def _aconf(self, gex_test, use_json):
        conf = AuditConf('localhost', 22)
        conf.gex_test = gex_test
        conf.json = use_json
        conf.batch = True
        conf.colors = False
        return conf

    def test_json_granular_output_expresses_inconclusive(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_disconnect()
        aconf = self._aconf('1024', True)
        from ssh_audit.ssh_audit import run_gex_granular_modulus_size_test
        rc = run_gex_granular_modulus_size_test(self.out, self._socket_like(), self._kex([GEX_SHA256]), aconf)
        assert rc == exitcodes.WARNING
        payload = json.loads(self.out.get_buffer())
        evidence = payload['dh-gex-evidence'][GEX_SHA256]
        assert evidence['inconclusive'] is True
        assert evidence['weak_observed'] is False
        assert evidence['observed_bits'] == []
        assert evidence['attempts'][0]['status'] == GEXStatus.REJECTED

    def test_json_granular_output_expresses_weak_group(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)
        aconf = self._aconf('1024', True)
        from ssh_audit.ssh_audit import run_gex_granular_modulus_size_test
        rc = run_gex_granular_modulus_size_test(self.out, self._socket_like(), self._kex([GEX_SHA256]), aconf)
        assert rc == exitcodes.FAILURE
        payload = json.loads(self.out.get_buffer())
        assert payload['dh-gex-modulus-size'] == {GEX_SHA256: [1024]}
        evidence = payload['dh-gex-evidence'][GEX_SHA256]
        assert evidence['weak_observed'] is True
        assert evidence['inconclusive'] is False
        assert evidence['observed_bits'] == [1024]

    def test_text_granular_output_expresses_rejection(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_disconnect()
        aconf = self._aconf('1024', False)
        from ssh_audit.ssh_audit import run_gex_granular_modulus_size_test
        rc = run_gex_granular_modulus_size_test(self.out, self._socket_like(), self._kex([GEX_SHA256]), aconf)
        assert rc == exitcodes.WARNING
        text = self.out.get_buffer()
        assert 'diffie-hellman group exchange modulus size' in text
        assert GEX_SHA256 in text and GEXStatus.REJECTED in text
        assert 'could not be determined' in text

    def test_standard_json_includes_evidence_and_inconclusive(self):
        from ssh_audit.ssh_audit import build_struct
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        for _ in range(8):
            server.queue_disconnect()
        kex = self._kex([GEX_SHA256])
        GEXTest.run(self.out, SSH_Socket(self.out, 'localhost', 22), None, kex)
        struct = build_struct('localhost', None, kex=kex)
        assert 'dh-gex' in struct
        assert struct['dh-gex'][GEX_SHA256]['inconclusive'] is True
        assert struct['dh-gex-inconclusive'][GEX_SHA256].find('refused') != -1

    def test_standard_json_weak_group_matches_text_failure(self):
        from ssh_audit.ssh_audit import build_struct
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)
        kex = self._kex([GEX_SHA256])
        GEXTest.run(self.out, SSH_Socket(self.out, 'localhost', 22), None, kex)
        struct = build_struct('localhost', None, kex=kex)
        kex_entry = next(e for e in struct['kex'] if e['algorithm'] == GEX_SHA256)
        assert kex_entry['keysize'] == 1024
        assert 'fail' in kex_entry['notes']
        assert struct['dh-gex'][GEX_SHA256]['weak_observed'] is True
        # The same failure text is what the text report renders via the DB.
        assert any('using small 1024-bit modulus' in n for n in kex_entry['notes']['fail'])


# pylint: disable=attribute-defined-outside-init
class TestGEXPolicy:
    @pytest.fixture(autouse=True)
    def init(self, virtual_socket, monkeypatch):
        self.vsocket = virtual_socket
        self.monkeypatch = monkeypatch
        self.out = OutputBuffer()
        GEXTest.reset_evidence()
        self._db_snapshot = copy.deepcopy(SSH2_KexDB.get_db())
        yield
        SSH2_KexDB.get_db().clear()
        SSH2_KexDB.get_db().update(copy.deepcopy(self._db_snapshot))

    def _kex(self, kex_algs):
        party = SSH2_KexParty(['aes128-ctr'], ['hmac-sha1'], ['none'], [''])
        return SSH2_Kex(self.out, b'\x00' * 16, kex_algs, ['ssh-rsa'], party, party, False)

    def _policy(self, expected_size):
        policy_data = '''name = "Test Policy"
version = 1
compressions = none
host keys = ssh-rsa
key exchanges = %s
ciphers = aes128-ctr
macs = hmac-sha1
dh_modulus_size_diffie-hellman-group-exchange-sha256 = %d
''' % (GEX_SHA256, expected_size)
        return Policy(policy_data=policy_data)

    def test_policy_fails_when_evidence_inconclusive(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        for _ in range(8):
            server.queue_disconnect()
        kex = self._kex([GEX_SHA256])
        GEXTest.run(self.out, SSH_Socket(self.out, 'localhost', 22), None, kex)
        assert GEX_SHA256 in kex.gex_inconclusive()

        policy = self._policy(3072)
        ok, _errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ok is False
        assert 'modulus sizes' in error_str
        assert 'unverified' in error_str

    def test_policy_fails_on_observed_weak_group(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(1024)
        kex = self._kex([GEX_SHA256])
        GEXTest.run(self.out, SSH_Socket(self.out, 'localhost', 22), None, kex)
        policy = self._policy(3072)
        ok, _errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ok is False
        assert '1024' in error_str

    def test_policy_passes_on_matching_observed_group(self):
        server = FakeGEXServer(self.vsocket, [GEX_SHA256], self.monkeypatch)
        server.queue_group(3072)
        kex = self._kex([GEX_SHA256])
        GEXTest.run(self.out, SSH_Socket(self.out, 'localhost', 22), None, kex)
        policy = self._policy(3072)
        ok, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ok is True
        assert len(errors) == 0
        assert len(error_str) == 0


class TestGEXAttemptSerialization:
    def test_attempt_dict_shape(self):
        GEXTest.reset_evidence()
        ok = GEXAttempt(512, 1024, 1536, GEXStatus.SUCCESS, 1024)
        assert ok.to_dict() == {
            'request': {'min': 512, 'pref': 1024, 'max': 1536},
            'status': GEXStatus.SUCCESS,
            'observed_bits': 1024,
        }
        rejected = GEXAttempt(512, 512, 512, GEXStatus.REJECTED, None, 'nope')
        d = rejected.to_dict()
        assert d['status'] == GEXStatus.REJECTED
        assert 'observed_bits' not in d
        assert d['error'] == 'nope'
        assert json.dumps(GEXTest.evidence_struct()) == '{}'
