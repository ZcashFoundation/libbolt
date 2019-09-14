import unittest
import libbolt
import ast, random, json

def rand_hex(stringLength=10):
    """Generate a random hex string of fixed length """
    hex_letters = '0123456789abcdef'
    return ''.join(random.choice(hex_letters) for i in range(stringLength))

def malformed_token(token):
    token_dict = ast.literal_eval(token)
    updated_token = {}
    for k,v in token_dict.items():
        if type(v) == str:
            updated_token[k] = v[:-4] + rand_hex(4)
        else:
            updated_token[k] = v
    return json.dumps(updated_token)

def malformed_proof(proof):
    bad_proof = proof.replace("0", "1")
    bad_proof = bad_proof.replace("1", "2")
    return bad_proof

class BoltEstablishTests(unittest.TestCase):
    def setUp(self):
        self.bolt = libbolt.Libbolt('target/{}/{}bolt.{}'.format(libbolt.mode, libbolt.prefix, libbolt.ext))
        self.channel_state = self.bolt.channel_setup("Test Channel")
        self.b0_cust = 1000
        self.b0_merch = 100
        (self.channel_token, self.merch_state, self.channel_state) = self.bolt.bidirectional_init_merchant(self.channel_state, self.b0_merch, "Bob")
        (channel_token, self.cust_state) = self.bolt.bidirectional_init_customer(self.channel_state, self.channel_token,
                                                                                 self.b0_cust, self.b0_merch, "Alice")

        # generate some bad stuff here
        larger_b0_cust = 2000
        (channel_token_bad, self.cust_state_bad) = self.bolt.bidirectional_init_customer(self.channel_state, self.channel_token,
                                                                                         larger_b0_cust, self.b0_merch, "Alice")

        # set them
        self.channel_token = channel_token
        self.channel_token_bad = channel_token_bad


    def test_establish_works_okay(self):
        """
        Establish protocol common case works
        """
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token, self.cust_state)

        cust_state_dict = json.loads(cust_state)
        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, cust_state_dict["pk_c"], self.b0_cust, self.b0_merch, self.merch_state)
        self.assertTrue(close_token is not None)

        (is_token_valid, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, close_token)
        self.assertTrue(is_token_valid)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(channel_state, com, self.merch_state)
        self.assertTrue(pay_token is not None)

        (is_channel_established, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_final(channel_state, cust_state, pay_token)

        self.assertTrue(is_channel_established)
        #print("Establish protocol works as expected.")

    def test_establish_merchant_issue_close_token_fail_as_expected(self):
        """
        Initial com proof fails as expected when commitment opening doesn't match expected initial customer and merchant balances
        """
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token_bad, self.cust_state_bad)

        cust_state_dict = json.loads(cust_state)
        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, cust_state_dict["pk_c"], self.b0_cust, self.b0_merch, self.merch_state)
        self.assertTrue(close_token is None)
        #print("Establish protocol fail works as expected.")

    def test_establish_customer_verify_close_token_fail_as_expected(self):
        """
        Not-signed close token fails to verify
        """
        close_token = json.dumps({"h":"b896166d76a7bd02565b6431dca27da4c290e234edfbca8d9189f78311e18f66a138684c91efdf7fd1c4b192bf27f68e",
                                  "H":"add6c20994749185fb7d44f8f5f1f3dbbcd250e4922a9c6c9017c25dda670d94c4b279b7f0fccd56916bf737a29a1938"})
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token, self.cust_state)

        (is_token_valid, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, close_token)
        self.assertTrue(is_token_valid is False)

    def test_establish_merchant_issue_pay_token_fail_as_expected(self):
        """
        Specifying a different commitment leads to an invalid pay token as expected
        """
        bad_com = json.dumps({"c":"852a57e24a2192e1cea19157e44f92d58369751f2012bc1f4a4312a89a63c74a92a4cb1d362b37ae0eda3b3bd1333502"})
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token, self.cust_state)

        cust_state_dict = json.loads(cust_state)
        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, cust_state_dict["pk_c"], self.b0_cust, self.b0_merch, self.merch_state)
        self.assertTrue(close_token is not None)

        (is_token_valid, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, close_token)
        self.assertTrue(is_token_valid)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(channel_state, bad_com, self.merch_state)
        self.assertTrue(pay_token is not None)

        (is_channel_established, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_final(channel_state, cust_state, pay_token)

        self.assertFalse(is_channel_established)

    def test_establish_not_complete_without_close_token(self):
        """
        Test that missing close token prevents the customer from establishing
        """
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token, self.cust_state)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(self.channel_state, com, self.merch_state)
        self.assertTrue(pay_token is not None)

        (is_channel_established, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_final(self.channel_state, cust_state, pay_token)

        self.assertFalse(is_channel_established)

    def test_error_handling_with_serialization(self):
        """
        Test that malformed close and/or pay token results in failure
        :return:
        """
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token, self.cust_state)

        cust_state_dict = json.loads(cust_state)
        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, cust_state_dict["pk_c"], self.b0_cust, self.b0_merch, self.merch_state)
        self.assertTrue(close_token is not None)

        malformed_close_token = malformed_token(close_token)
        (is_token_valid, bad_channel_state, bad_cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, malformed_close_token)
        self.assertTrue(is_token_valid is None)

        (is_token_valid, self.channel_state, cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, close_token)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(self.channel_state, com, self.merch_state)
        malformed_pay_token = malformed_token(pay_token)

        (is_channel_established, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_final(self.channel_state, cust_state, malformed_pay_token)
        self.assertFalse(is_channel_established)

class BoltPayTests(unittest.TestCase):
    def setUp(self):
        """
        Setup init customer/merchant state and establish phase of Bolt protocol
        :return:
        """
        self.bolt = libbolt.Libbolt('target/{}/{}bolt.{}'.format(libbolt.mode, libbolt.prefix, libbolt.ext))
        self.channel_state = self.bolt.channel_setup("Test Channel")
        self.b0_cust = 500
        self.b0_merch = 10
        (self.channel_token, self.merch_state, self.channel_state) = self.bolt.bidirectional_init_merchant(self.channel_state, self.b0_merch, "Bob")
        (self.channel_token, self.cust_state) = self.bolt.bidirectional_init_customer(self.channel_state, self.channel_token,
                                                                                      self.b0_cust, self.b0_merch, "Alice")

        (self.channel_token, self.cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(self.channel_token, self.cust_state)

        cust_state_dict = json.loads(self.cust_state)
        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, cust_state_dict["pk_c"], self.b0_cust, self.b0_merch, self.merch_state)
        self.assertTrue(close_token is not None)

        (is_token_valid, self.channel_state, self.cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, self.cust_state, close_token)
        self.assertTrue(is_token_valid)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(self.channel_state, com, self.merch_state)
        self.assertTrue(pay_token is not None)

        (is_channel_established, self.channel_state, self.cust_state) = self.bolt.bidirectional_establish_customer_final(self.channel_state, self.cust_state, pay_token)

        self.assertTrue(is_channel_established)

    def test_pay_protocol_works(self):
        """
        Payment protocol works
        :return:
        """
        amount = 10
        (payment_proof, new_cust_state) = self.bolt.bidirectional_pay_generate_payment_proof(self.channel_state, self.cust_state, amount)

        (new_close_token, self.merch_state) = self.bolt.bidirectional_pay_verify_payment_proof(self.channel_state, payment_proof, self.merch_state)

        (revoke_token, self.cust_state) = self.bolt.bidirectional_pay_generate_revoke_token(self.channel_state, self.cust_state, new_cust_state, new_close_token)

        (pay_token, self.merch_state) = self.bolt.bidirectional_pay_verify_revoke_token(revoke_token, self.merch_state)

        (self.cust_state, is_pay_valid) = self.bolt.bidirectional_pay_verify_payment_token(self.channel_state, self.cust_state, pay_token)
        self.assertTrue(is_pay_valid)

    def test_pay_protocol_bad_payment_proof_fail_handled(self):
        """
        Payment protocol fails as expected when customer sends a bad payment proof
        :return:
        """
        amount = 15
        (payment_proof, new_cust_state) = self.bolt.bidirectional_pay_generate_payment_proof(self.channel_state, self.cust_state, amount)

        bad_payment_proof = malformed_proof(payment_proof)
        (new_close_token, self.merch_state) = self.bolt.bidirectional_pay_verify_payment_proof(self.channel_state, bad_payment_proof, self.merch_state)
        self.assertTrue(new_close_token is None)

    def test_pay_protocol_bad_close_token_fail_handled(self):
        """
        Payment protocol fails as expected when merchant returns a malformed/bad close token
        :return:
        """
        amount = 10
        (payment_proof, new_cust_state) = self.bolt.bidirectional_pay_generate_payment_proof(self.channel_state, self.cust_state, amount)

        (new_close_token, self.merch_state) = self.bolt.bidirectional_pay_verify_payment_proof(self.channel_state, payment_proof, self.merch_state)
        bad_close_token = malformed_token(new_close_token)

        (revoke_token, self.cust_state) = self.bolt.bidirectional_pay_generate_revoke_token(self.channel_state, self.cust_state, new_cust_state, bad_close_token)
        self.assertTrue(revoke_token is None)

    def test_pay_protocol_bad_revoke_token_fail_handled(self):
        """
        Payment protocol fails as expected when customer sends a bad revoke token
        :return:
        """
        amount = 20
        (payment_proof, new_cust_state) = self.bolt.bidirectional_pay_generate_payment_proof(self.channel_state, self.cust_state, amount)

        (new_close_token, self.merch_state) = self.bolt.bidirectional_pay_verify_payment_proof(self.channel_state, payment_proof, self.merch_state)

        (revoke_token, self.cust_state) = self.bolt.bidirectional_pay_generate_revoke_token(self.channel_state, self.cust_state, new_cust_state, new_close_token)

        bad_revoke_token = malformed_token(revoke_token)
        (pay_token, merch_state) = self.bolt.bidirectional_pay_verify_revoke_token(bad_revoke_token, self.merch_state)
        self.assertTrue(pay_token is None)

    def test_pay_protocol_bad_payment_token_fail_handled(self):
        """
        Payment protocol fails as expected when merchant returns a malformed pay token
        :return:
        """
        amount = 25
        (payment_proof, new_cust_state) = self.bolt.bidirectional_pay_generate_payment_proof(self.channel_state, self.cust_state, amount)

        (new_close_token, self.merch_state) = self.bolt.bidirectional_pay_verify_payment_proof(self.channel_state, payment_proof, self.merch_state)

        (revoke_token, self.cust_state) = self.bolt.bidirectional_pay_generate_revoke_token(self.channel_state, self.cust_state, new_cust_state, new_close_token)

        (pay_token, self.merch_state) = self.bolt.bidirectional_pay_verify_revoke_token(revoke_token, self.merch_state)
        bad_pay_token = malformed_token(pay_token)

        (cust_state, is_pay_valid) = self.bolt.bidirectional_pay_verify_payment_token(self.channel_state, self.cust_state, bad_pay_token)
        self.assertTrue(is_pay_valid is None)

class BoltMultiChannelTests(unittest.TestCase):
    def setUp(self):
        """
        Setup init customer/merchant state and establish phase of Bolt protocol
        :return:
        """
        self.bolt = libbolt.Libbolt('target/{}/{}bolt.{}'.format(libbolt.mode, libbolt.prefix, libbolt.ext))
        self.channel_state = self.bolt.channel_setup("Test Channel")
        self.b0_alice = self.b0_charlie = 150
        self.b0_merch = 5
        (self.channel_token, self.merch_state, self.channel_state) = self.bolt.bidirectional_init_merchant(self.channel_state, self.b0_merch, "Bob")

        (self.channel_token_a, self.alice_state) = self.bolt.bidirectional_init_customer(self.channel_state, self.channel_token,
                                                                                      self.b0_alice, self.b0_merch, "Alice")

        (self.channel_token_c, self.charlie_state) = self.bolt.bidirectional_init_customer(self.channel_state, self.channel_token,
                                                                                      self.b0_charlie, self.b0_merch, "Charlie")

    def _establish_channel(self, channel_token, channel_state, cust_state, pkc, b0_cust, b0_merch):
        (channel_token, cust_state, com, com_proof) = self.bolt.bidirectional_establish_customer_generate_proof(channel_token, cust_state)

        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(channel_state, com, com_proof, pkc, b0_cust, b0_merch, self.merch_state)
        self.assertTrue(close_token is not None)

        (is_token_valid, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(channel_state, cust_state, close_token)
        self.assertTrue(is_token_valid)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(channel_state, com, self.merch_state)
        self.assertTrue(pay_token is not None)

        (is_channel_established, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_final(channel_state, cust_state, pay_token)
        self.assertTrue(is_channel_established)

        return channel_token, channel_state, cust_state

    def _pay_on_channel(self, channel_state, cust_state, amount):
        (payment_proof, new_cust_state) = self.bolt.bidirectional_pay_generate_payment_proof(channel_state, cust_state, amount)

        (new_close_token, self.merch_state) = self.bolt.bidirectional_pay_verify_payment_proof(channel_state, payment_proof, self.merch_state)

        (revoke_token, cust_state) = self.bolt.bidirectional_pay_generate_revoke_token(channel_state, cust_state, new_cust_state, new_close_token)

        (pay_token, self.merch_state) = self.bolt.bidirectional_pay_verify_revoke_token(revoke_token, self.merch_state)

        (cust_state, is_pay_valid) = self.bolt.bidirectional_pay_verify_payment_token(channel_state, cust_state, pay_token)
        self.assertTrue(is_pay_valid)

        return channel_state, cust_state


    def test_multiple_channels_work(self):
        """Establishing concurrent channels with a merchant works as expected
        """
        alice_cust_state_dict = json.loads(self.alice_state)
        self.channel_token_a, self.channel_state_a, alice_cust_state = self._establish_channel(self.channel_token_a, self.channel_state,
                                                                                               self.alice_state, alice_cust_state_dict["pk_c"],
                                                                                               self.b0_alice, self.b0_merch)

        charlie_cust_state_dict = json.loads(self.charlie_state)
        self.channel_token_c, self.channel_state_c, charlie_cust_state = self._establish_channel(self.channel_token_c, self.channel_state,
                                                                                                 self.charlie_state, charlie_cust_state_dict["pk_c"],
                                                                                                 self.b0_charlie, self.b0_merch)

        self.channel_state_a, alice_cust_state = self._pay_on_channel(self.channel_state_a, alice_cust_state, 15)
        #print("Alice cust state => ", alice_cust_state)
        self.channel_state_c, charlie_cust_state = self._pay_on_channel(self.channel_state_c, charlie_cust_state, 10)
        self.channel_state_c, charlie_cust_state = self._pay_on_channel(self.channel_state_c, charlie_cust_state, 20)
        #print("Charlie cust state => ", charlie_cust_state)

        alice_bal = json.loads(alice_cust_state)["cust_balance"]
        charlie_bal = json.loads(charlie_cust_state)["cust_balance"]

        self.assertTrue(alice_bal != charlie_bal)



class BoltIntermediaryTests(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
