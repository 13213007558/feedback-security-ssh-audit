import hashlib
import pytest
from datetime import date

from ssh_audit.builtin_policies import BUILTIN_POLICIES
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.writebuf import WriteBuf


class TestPolicy:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = OutputBuffer
        self.Policy = Policy
        self.wbuf = WriteBuf
        self.ssh2_kex = SSH2_Kex


    def _get_kex(self):
        '''Returns an SSH2.Kex object to simulate a server connection.'''

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['kex_alg1', 'kex_alg2'])
        w.write_list(['key_alg1', 'key_alg2'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return self.ssh2_kex.parse(self.OutputBuffer, w.write_flush())


    def _get_kex_custom(self, kex_algs=None, key_algs=None, cli_enc=None, srv_enc=None, cli_mac=None, srv_mac=None, cli_comp=None, srv_comp=None):
        '''Builds an offline SSH2_Kex object whose client-to-server and server-to-client lists can differ, so directional negotiation can be tested independently.'''

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(kex_algs if kex_algs is not None else ['kex_alg1', 'kex_alg2'])
        w.write_list(key_algs if key_algs is not None else ['key_alg1', 'key_alg2'])
        w.write_list(cli_enc if cli_enc is not None else ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(srv_enc if srv_enc is not None else ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(cli_mac if cli_mac is not None else ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(srv_mac if srv_mac is not None else ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(cli_comp if cli_comp is not None else ['comp_alg1', 'comp_alg2'])
        w.write_list(srv_comp if srv_comp is not None else ['comp_alg1', 'comp_alg2'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return self.ssh2_kex.parse(self.OutputBuffer, w.write_flush())


    def test_builtin_policy_consistency(self):
        '''Ensure that the BUILTIN_POLICIES struct is consistent.'''

        for policy_name in BUILTIN_POLICIES:

            # Ensure that all required fields are present.
            required_fields = ['version', 'changelog', 'banner', 'compressions', 'host_keys', 'optional_host_keys', 'kex', 'ciphers', 'macs', 'hostkey_sizes', 'dh_modulus_sizes', 'server_policy']
            for field in required_fields:
                assert field in BUILTIN_POLICIES[policy_name]

            # Ensure that the policy name ends with " (version X)", where X is the 'version' field.
            version_str = " (version %s)" % BUILTIN_POLICIES[policy_name]['version']
            assert policy_name.endswith(version_str)

            # Ensure version field is a string, but can be parsed as an integer.
            version_field = BUILTIN_POLICIES[policy_name]['version']
            assert type(version_field) is str
            try:
                int(version_field)
            except ValueError:
                assert False, "version field of %s policy is not parseable as an integer." % policy_name

            # Ensure that the changelog field is a string and non-empty.
            assert type(BUILTIN_POLICIES[policy_name]['changelog']) is str
            assert len(BUILTIN_POLICIES[policy_name]['changelog']) > 0

            # Ensure that at least one host key is defined.
            assert type(BUILTIN_POLICIES[policy_name]['host_keys']) is list
            assert len(BUILTIN_POLICIES[policy_name]['host_keys']) > 0

            # Ensure that at least one key exchange is defined.
            assert type(BUILTIN_POLICIES[policy_name]['kex']) is list
            assert len(BUILTIN_POLICIES[policy_name]['kex']) > 0

            # Ensure that at least one cipher is defined.
            assert type(BUILTIN_POLICIES[policy_name]['ciphers']) is list
            assert len(BUILTIN_POLICIES[policy_name]['ciphers']) > 0

            # Ensure that at least one MAC is defined
            assert type(BUILTIN_POLICIES[policy_name]['macs']) is list
            assert len(BUILTIN_POLICIES[policy_name]['macs']) > 0

            # These tests apply to server policies only.
            if BUILTIN_POLICIES[policy_name]['server_policy']:
                assert type(BUILTIN_POLICIES[policy_name]['hostkey_sizes']) is dict
                assert len(BUILTIN_POLICIES[policy_name]['hostkey_sizes']) > 0

                # Examine all the hostkey_sizes entries...
                for hostkey_type in BUILTIN_POLICIES[policy_name]['hostkey_sizes']:
                    hostkey_data = BUILTIN_POLICIES[policy_name]['hostkey_sizes'][hostkey_type]

                    # Ensure that 'hostkey_size' is always included and that it is an integer.
                    assert 'hostkey_size' in hostkey_data
                    assert type(hostkey_data['hostkey_size']) is int

                    # If this is an ed25519 host key, ensure its size is fixed at 256.  If its an RSA host key, ensure the size is 4096.
                    if hostkey_type.find('ed25519') != -1:
                        assert int(hostkey_data['hostkey_size']) == 256
                    elif hostkey_type.startswith('rsa-'):
                        assert int(hostkey_data['hostkey_size']) == 4096
                    else:  # Catch unexpected host key types.
                        assert False

                    # Ensure either that 'ca_key_type' and 'ca_key_size' are both present, or neither are.  Fail cases when only one of the fields are present.
                    assert (('ca_key_type' in hostkey_data) and ('ca_key_size' in hostkey_data)) or (('ca_key_type' not in hostkey_data) and ('ca_key_size' not in hostkey_data))

                    # Ensure that the ca_key_type is either ssh-rsa or ssh-ed25519.
                    if 'ca_key_type' in hostkey_data:
                        assert hostkey_data['ca_key_type'] in ['ssh-rsa', 'ssh-ed25519']

                    # Ensure RSA CA key sizes are fixed at 4096.  Ensure ED25519 CA keys are 256.
                    if 'ca_key_size' in hostkey_data:
                        if 'ca_key_type' == 'ssh-rsa':
                            assert hostkey_data['ca_key_size'] == 4096
                        elif 'ca_key_type' == 'ssh-ed25519':
                            assert hostkey_data['ca_key_size'] == 256

                # Ensure that the 'dh_modulus_size' field is a dict.
                assert type(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']) is dict

                # The 'dh_modulus_size' field should have either one entry, or be empty.
                assert len(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']) in range(0, 2)  # The endpoint in range() is not inclusive

                # If 'diffie-hellman-group-exchange-sha256' is in the kex list, ensure that it exists in the 'dh_modulus_sizes' entry.  That entry must be defined for 2048 bits or larger.
                if 'diffie-hellman-group-exchange-sha256' in BUILTIN_POLICIES[policy_name]['kex']:
                    assert 'diffie-hellman-group-exchange-sha256' in BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']
                    assert int(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']['diffie-hellman-group-exchange-sha256']) >= 2048

            else:  # Client-specific tests.

                # These must be set to None for client policies, since they have no meaning otherwise.
                assert BUILTIN_POLICIES[policy_name]['hostkey_sizes'] is None
                assert BUILTIN_POLICIES[policy_name]['dh_modulus_sizes'] is None

            # Ensure that each built-in policy can be loaded with Policy.load_builtin_policy().
            assert Policy.load_builtin_policy(policy_name) is not None

        # Ensure that both server and client policy names are returned.
        server_policy_names, client_policy_names = Policy.list_builtin_policies(False)
        assert len(server_policy_names) > 0
        assert len(client_policy_names) > 0


    def test_policy_basic(self):
        '''Ensure that a basic policy can be parsed correctly.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        assert str(policy) == "Name: [Test Policy]\nVersion: [1]\nAllow Algorithm Subset and/or Reordering: False\nAllow Host Key Subset and/or Reordering: False\nBanner: {undefined}\nCompressions: comp_alg1\nHost Keys: key_alg1\nOptional Host Keys: {undefined}\nKey Exchanges: kex_alg1, kex_alg2\nCiphers: cipher_alg1, cipher_alg2, cipher_alg3\nMACs: mac_alg1, mac_alg2, mac_alg3\nHost Key Sizes: {undefined}\nDH Modulus Sizes: {undefined}\nServer Policy: True"


    def test_policy_invalid_1(self):
        '''Basic policy, but with 'ciphersx' instead of 'ciphers'.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphersx = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_2(self):
        '''Basic policy, but is missing the required name field.'''

        policy_data = '''# This is a comment
#name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_3(self):
        '''Basic policy, but is missing the required version field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
#version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_4(self):
        '''Basic policy, but is missing quotes in the name field.'''

        policy_data = '''# This is a comment
name = Test Policy
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_5(self):
        '''Basic policy, but is missing quotes in the banner field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

banner = 0mg
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_6(self):
        '''Basic policy, but is missing quotes in the header field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

header = 0mg
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_create_1(self):
        '''Creates a policy from a kex and ensures it is generated exactly as expected.'''

        kex = self._get_kex()
        pol_data = self.Policy.create('www.l0l.com', 'bannerX', kex, False)

        # Today's date is embedded in the policy, so filter it out to get repeatable results.
        pol_data = pol_data.replace(date.today().strftime('%Y/%m/%d'), '[todays date]')

        # Instead of writing out the entire expected policy--line by line--just check that it has the expected hash.
        assert hashlib.sha256(pol_data.encode('ascii')).hexdigest() == '3862e56ea60c1ecba6dffbf724216c4391b6fe00a790b0075617477d4addf761'


    def test_policy_evaluate_passing_1(self):
        '''Creates a policy and evaluates it against the same server'''

        kex = self._get_kex()
        policy_data = self.Policy.create('www.l0l.com', None, kex, False)
        policy = self.Policy(policy_data=policy_data)

        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0
        print(error_str)
        assert len(error_str) == 0


    def test_policy_evaluate_failing_1(self):
        '''Ensure that a policy with a specified banner fails against a server with a different banner'''

        policy_data = '''name = "Test Policy"
version = 1
banner = "XXX mismatched banner XXX"
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Banner did not match.') != -1


    def test_policy_evaluate_failing_2(self):
        '''Ensure that a mismatched compressions list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = XXXmismatchedXXX, comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 2
        assert error_str.find('Compression (client-to-server) did not match.') != -1
        assert error_str.find('Compression (server-to-client) did not match.') != -1


    def test_policy_evaluate_failing_3(self):
        '''Ensure that a mismatched host keys results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = XXXmismatchedXXX, key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Host keys did not match.') != -1


    def test_policy_evaluate_failing_4(self):
        '''Ensure that a mismatched key exchange list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = XXXmismatchedXXX, kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Key exchanges did not match.') != -1


    def test_policy_evaluate_failing_5(self):
        '''Ensure that a mismatched cipher list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, XXXmismatched, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 2
        assert error_str.find('Ciphers (client-to-server) did not match.') != -1
        assert error_str.find('Ciphers (server-to-client) did not match.') != -1


    def test_policy_evaluate_failing_6(self):
        '''Ensure that a mismatched MAC list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, XXXmismatched, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 2
        assert error_str.find('MACs (client-to-server) did not match.') != -1
        assert error_str.find('MACs (server-to-client) did not match.') != -1


    def test_policy_evaluate_failing_7(self):
        '''Ensure that a mismatched host keys and MACs results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2, XXXmismatchedXXX
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, XXXmismatchedXXX, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 3
        assert error_str.find('Host keys did not match.') != -1
        assert error_str.find('MACs (client-to-server) did not match.') != -1
        assert error_str.find('MACs (server-to-client) did not match.') != -1


    def test_policy_evaluate_subset_passing_1(self):
        '''Ensure that exact algorithm matches work even when subset parsing is enabled.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""


    def test_policy_evaluate_subset_passing_2(self):
        '''Ensure that subset parsing works.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""


    def test_policy_evaluate_subset_failing_1(self):
        '''Ensure that subset parsing returns a failure.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg7, key_alg8, key_alg9
key exchanges = kex_alg7, kex_alg8, kex_alg9
ciphers = cipher_alg7, cipher_alg8, cipher_alg9, cipher_alg10
macs = mac_alg7, mac_alg8, mac_alg9, mac_alg10'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 6
        assert error_str.find("Ciphers (client-to-server) did not match.") != -1
        assert error_str.find("Ciphers (server-to-client) did not match.") != -1
        assert error_str.find("Host keys did not match.") != -1
        assert error_str.find("MACs (client-to-server) did not match.") != -1
        assert error_str.find("MACs (server-to-client) did not match.") != -1
        assert error_str.find("Key exchanges did not match.") != -1


    def test_policy_evaluate_subset_failing_2(self):
        '''Ensure that subset parsing returns a failure when policy includes kex-strict-s-v00@openssh.com, but target does not.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2, kex-strict-s-v00@openssh.com
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert errors[0]['mismatched_field'] == 'Key exchanges (server-to-client)'
        assert errors[0]['reason'] == 'required security marker kex-strict-s-v00@openssh.com is missing from the server-to-client key exchange list'
        assert error_str.find("Key exchanges (server-to-client) did not match.") != -1
        assert error_str.find("Reason:") != -1


    def test_policy_evaluate_subset_failing_3(self):
        '''Ensure that subset parsing returns a failure when policy includes kex-strict-c-v00@openssh.com, but target does not.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2, kex-strict-c-v00@openssh.com
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert errors[0]['mismatched_field'] == 'Key exchanges (client-to-server)'
        assert errors[0]['reason'] == 'required security marker kex-strict-c-v00@openssh.com is missing from the client-to-server key exchange list'
        assert error_str.find("Key exchanges (client-to-server) did not match.") != -1
        assert error_str.find("Reason:") != -1


    #
    # Security regression tests for allow_algorithm_subset_and_reordering.
    # Security-critical negotiation markers (strict-KEX and ext-info) must be
    # enforced even when ordinary algorithm subsets/re-orderings are allowed,
    # and cipher/MAC lists are negotiated independently in each direction.
    #

    _SUBSET_POLICY_TEMPLATE = '''name = "Test Policy"
version = 1
{client_policy}allow_algorithm_subset_and_reordering = true
host keys = {host_keys}
key exchanges = {kex}
ciphers = {ciphers}
macs = {macs}'''

    def _subset_policy(self, kex, ciphers, macs, client_policy=False, host_keys=None):
        if host_keys is None:
            host_keys = 'key_alg1, key_alg2'
        return self.Policy(policy_data=self._SUBSET_POLICY_TEMPLATE.format(
            client_policy='client policy = true\n' if client_policy else '',
            host_keys=host_keys, kex=', '.join(kex), ciphers=', '.join(ciphers), macs=', '.join(macs)))

    def test_policy_subset_strict_kex_server_marker_present_passes(self):
        '''A server advertising the required strict-KEX (s) marker passes even with a reduced, re-ordered ordinary algorithm subset.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg2', 'kex-strict-s-v00@openssh.com'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'kex_alg3', 'kex-strict-s-v00@openssh.com'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""

    def test_policy_subset_strict_kex_server_marker_missing_fails(self):
        '''Dropping the strict-KEX (s) marker is a missing security condition, not an acceptable algorithm subset.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg2'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'kex_alg3', 'kex-strict-s-v00@openssh.com'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1
        assert errors[0]['mismatched_field'] == 'Key exchanges (server-to-client)'
        assert errors[0]['reason'].find('kex-strict-s-v00@openssh.com') != -1
        assert error_str.find('Key exchanges (server-to-client) did not match.') != -1

    def test_policy_subset_strict_kex_client_marker_present_passes(self):
        '''A client policy passes when the audited client advertises the strict-KEX (c) marker alongside an ordinary subset.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg1', 'kex-strict-c-v00@openssh.com'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'kex-strict-c-v00@openssh.com'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'], client_policy=True)
        ret, errors, error_str = policy.evaluate('SSH Client 1.0', kex)
        assert ret is True
        assert len(errors) == 0

    def test_policy_subset_strict_kex_client_marker_missing_fails(self):
        '''A client that drops the strict-KEX (c) marker fails, and the error names the client-to-server direction.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg1'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'kex-strict-c-v00@openssh.com'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'], client_policy=True)
        ret, errors, error_str = policy.evaluate('SSH Client 1.0', kex)
        assert ret is False
        assert len(errors) == 1
        assert errors[0]['mismatched_field'] == 'Key exchanges (client-to-server)'
        assert errors[0]['reason'].find('kex-strict-c-v00@openssh.com') != -1

    def test_policy_subset_ext_info_server_marker_not_falsely_reported(self):
        '''When ext-info (s) is present but the strict-KEX marker is missing, only the actually missing marker is reported.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg2', 'ext-info-s'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'ext-info-s', 'kex-strict-s-v00@openssh.com'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        # The target also lacks the strict marker, so that failure must be reported independently.
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        marker_errors = [e for e in errors if e['mismatched_field'] == 'Key exchanges (server-to-client)']
        assert len(marker_errors) == 1
        assert marker_errors[0]['reason'].find('kex-strict-s-v00@openssh.com') != -1
        # ext-info-s being present means it is never reported as missing.
        assert all('ext-info-s' not in e.get('reason', '') for e in errors)

    def test_policy_subset_ext_info_server_marker_missing_fails(self):
        '''Before the fix, a subset policy silently accepted a server without the required ext-info (s) marker.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg1', 'kex_alg2'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'ext-info-s'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1
        assert errors[0]['mismatched_field'] == 'Key exchanges (server-to-client)'
        assert errors[0]['reason'] == 'required security marker ext-info-s is missing from the server-to-client key exchange list'
        assert error_str.find('Reason:  required security marker ext-info-s') != -1

    def test_policy_subset_ext_info_client_marker_missing_fails(self):
        '''A client policy must reject a client that omits the ext-info (c) marker.'''

        kex = self._get_kex_custom(kex_algs=['kex_alg1'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'ext-info-c', 'kex-strict-c-v00@openssh.com'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'], ['mac_alg1', 'mac_alg2', 'mac_alg3'], client_policy=True)
        ret, errors, error_str = policy.evaluate('SSH Client 1.0', kex)
        assert ret is False
        missing_markers = set()
        for error in errors:
            if error['mismatched_field'] == 'Key exchanges (client-to-server)':
                for marker in ('ext-info-c', 'kex-strict-c-v00@openssh.com'):
                    if marker in error['reason']:
                        missing_markers.add(marker)
        assert missing_markers == {'ext-info-c', 'kex-strict-c-v00@openssh.com'}

    def test_policy_exact_mode_still_enforces_markers(self):
        '''Required markers are security conditions under exact-match policies too, with a direction in the error.'''

        policy_data = '''name = "Test Policy"
version = 1
key exchanges = kex_alg1, kex_alg2, ext-info-s, kex-strict-s-v00@openssh.com
host keys = key_alg1, key_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''
        policy = self.Policy(policy_data=policy_data)
        kex = self._get_kex_custom(kex_algs=['kex_alg1', 'kex_alg2', 'ext-info-s'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        marker_errors = [e for e in errors if 'reason' in e]
        assert len(marker_errors) == 1
        assert marker_errors[0]['mismatched_field'] == 'Key exchanges (server-to-client)'
        assert 'kex-strict-s-v00@openssh.com' in marker_errors[0]['reason']
        # The generic exact-list mismatch is still reported in addition to the marker failure.
        assert any(e['mismatched_field'] == 'Key exchanges' for e in errors)

    def test_policy_subset_bidirectional_cipher_mismatch_isolated(self):
        '''A disallowed cipher in only one direction fails just that direction; the compliant direction produces no error.'''

        # Server-to-client adds a cipher the policy does not allow; client-to-server stays within the policy.
        kex = self._get_kex_custom(
            cli_enc=['cipher_alg2', 'cipher_alg1'],
            srv_enc=['cipher_alg1', 'cipher_alg9'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2'], ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'],
            ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        cipher_errors = [e for e in errors if e['mismatched_field'].startswith('Ciphers')]
        assert len(cipher_errors) == 1
        assert cipher_errors[0]['mismatched_field'] == 'Ciphers (server-to-client)'
        assert cipher_errors[0]['reason'] == 'algorithm cipher_alg9 is not allowed in the server-to-client list'
        assert error_str.find('Ciphers (client-to-server)') == -1

    def test_policy_subset_bidirectional_cipher_mismatch_both_directions(self):
        '''Disallowed ciphers in both directions yield two independent errors, each tagged with its direction.'''

        kex = self._get_kex_custom(
            cli_enc=['cipher_alg8'],
            srv_enc=['cipher_alg9'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2'], ['cipher_alg1', 'cipher_alg2'], ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        fields = {e['mismatched_field'] for e in errors if e['mismatched_field'].startswith('Ciphers')}
        assert fields == {'Ciphers (client-to-server)', 'Ciphers (server-to-client)'}

    def test_policy_subset_bidirectional_mac_mismatch_isolated(self):
        '''A disallowed standalone MAC in only the client-to-server list is caught independently of the other direction.'''

        kex = self._get_kex_custom(
            cli_mac=['hmac-sha2-256', 'hmac-sha1-weak'],
            srv_mac=['hmac-sha2-256', 'hmac-sha2-512'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2'],
            ['aes256-ctr', 'aes128-ctr'],
            ['hmac-sha2-256', 'hmac-sha2-512'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        mac_errors = [e for e in errors if e['mismatched_field'].startswith('MACs')]
        assert len(mac_errors) == 1
        assert mac_errors[0]['mismatched_field'] == 'MACs (client-to-server)'
        assert 'hmac-sha1-weak' in mac_errors[0]['reason']
        assert error_str.find('MACs (server-to-client)') == -1

    def test_policy_subset_aead_and_standalone_mac_are_separate_lists(self):
        '''AEAD ciphers authenticate implicitly, but the separately negotiated MAC list (used by non-AEAD ciphers) is still validated per direction.'''

        # Both directions negotiate the same AEAD-capable ciphers; the MAC lists (relevant for aes*-ctr) differ in strength.
        aead_ciphers = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes256-ctr']
        kex = self._get_kex_custom(
            cli_enc=aead_ciphers, srv_enc=aead_ciphers,
            cli_mac=['hmac-sha2-256-etm@openssh.com', 'hmac-md5-weak'],
            srv_mac=['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2'], aead_ciphers,
            ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        # No cipher errors: the AEAD lists match the policy in both directions.
        assert not any(e['mismatched_field'].startswith('Ciphers') for e in errors)
        # Exactly one MAC error, proving the MAC list is not collapsed into the cipher/AEAD data.
        mac_errors = [e for e in errors if e['mismatched_field'].startswith('MACs')]
        assert len(mac_errors) == 1
        assert mac_errors[0]['mismatched_field'] == 'MACs (client-to-server)'
        assert 'hmac-md5-weak' in mac_errors[0]['reason']

    def test_policy_subset_aead_only_compliant_passes(self):
        '''When both directions stay within the allowed AEAD ciphers and MAC subsets, evaluation passes.'''

        aead_ciphers = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com']
        kex = self._get_kex_custom(
            cli_enc=['aes256-gcm@openssh.com'],
            srv_enc=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
            cli_mac=['hmac-sha2-256-etm@openssh.com'],
            srv_mac=['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2'], aead_ciphers,
            ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""

    def test_policy_exact_mode_bidirectional_mismatch(self):
        '''Under exact matching, a directional-only cipher difference is still detected in both directions independently.'''

        policy_data = '''name = "Test Policy"
version = 1
key exchanges = kex_alg1, kex_alg2
host keys = key_alg1, key_alg2
ciphers = cipher_alg1, cipher_alg2
macs = mac_alg1, mac_alg2'''
        policy = self.Policy(policy_data=policy_data)
        kex = self._get_kex_custom(
            cli_enc=['cipher_alg1', 'cipher_algX'],
            srv_enc=['cipher_alg1', 'cipher_alg2'],
            cli_mac=['mac_alg1', 'mac_alg2'],
            srv_mac=['mac_alg1', 'mac_alg2'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        cipher_errors = [e for e in errors if e['mismatched_field'].startswith('Ciphers')]
        assert len(cipher_errors) == 1
        assert cipher_errors[0]['mismatched_field'] == 'Ciphers (client-to-server)'
        assert not any(e['mismatched_field'].startswith('MACs') for e in errors)

    def test_policy_subset_ordinary_algorithms_still_tolerated(self):
        '''Plain algorithm removal and re-ordering without marker involvement remains allowed by the subset option.'''

        kex = self._get_kex_custom(
            kex_algs=['kex_alg2', 'kex_alg1'],
            cli_enc=['cipher_alg3'], srv_enc=['cipher_alg3', 'cipher_alg1'],
            cli_mac=['mac_alg2'], srv_mac=['mac_alg2', 'mac_alg1'])
        policy = self._subset_policy(
            ['kex_alg1', 'kex_alg2', 'kex_alg3'],
            ['cipher_alg1', 'cipher_alg2', 'cipher_alg3'],
            ['mac_alg1', 'mac_alg2', 'mac_alg3'])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""
