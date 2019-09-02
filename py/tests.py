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
        updated_token[k] = rand_hex(1) + v[1:]
    return json.dumps(updated_token)

class BoltEstablishTests(unittest.TestCase):
    def setUp(self):
        self.bolt = libbolt.Libbolt('target/{}/{}bolt.{}'.format(libbolt.mode, libbolt.prefix, libbolt.ext))
        self.channel_state = self.bolt.channel_setup("Test Channel")
        self.b0_cust = 1000
        self.b0_merch = 100
        (self.channel_token, self.merch_state) = self.bolt.bidirectional_init_merchant(self.channel_state, self.b0_merch, "Bob")
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

        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, self.b0_cust, self.b0_merch, self.merch_state)
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

        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, self.b0_cust, self.b0_merch, self.merch_state)
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

        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, self.b0_cust, self.b0_merch, self.merch_state)
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

        close_token = self.bolt.bidirectional_establish_merchant_issue_close_token(self.channel_state, com, com_proof, self.b0_cust, self.b0_merch, self.merch_state)
        self.assertTrue(close_token is not None)

        malformed_close_token = malformed_token(close_token)
        (is_token_valid, bad_channel_state, bad_cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, malformed_close_token)
        self.assertTrue(is_token_valid is None)

        (is_token_valid, self.channel_state, cust_state) = self.bolt.bidirectional_establish_customer_verify_close_token(self.channel_state, cust_state, close_token)

        pay_token = self.bolt.bidirectional_establish_merchant_issue_pay_token(self.channel_state, com, self.merch_state)
        malformed_pay_token = malformed_token(pay_token)

        (is_channel_established, channel_state, cust_state) = self.bolt.bidirectional_establish_customer_final(self.channel_state, cust_state, malformed_pay_token)
        self.assertFalse(is_channel_established)

if __name__ == '__main__':
    unittest.main()
