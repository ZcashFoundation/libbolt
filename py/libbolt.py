from ctypes import cdll
from sys import platform

import sys, ctypes
from ctypes import c_void_p, c_uint8

import ast
import json

class Libbolt(object):
	"""Libbolt Py/C low-level API"""

	def __init__(self, path):
		self.lib = cdll.LoadLibrary(path)
		self.load_library_params()

	def load_library_params(self):
		self.lib.ffishim_bidirectional_channel_setup.argtypes = (c_void_p, c_uint8)
		self.lib.ffishim_bidirectional_channel_setup.restype = c_void_p

		# ESTABLISH PROTOCOL

		self.lib.ffishim_bidirectional_init_merchant.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_init_merchant.restype = c_void_p

		self.lib.ffishim_bidirectional_init_customer.argtypes = (c_void_p, ctypes.c_int32, ctypes.c_int32, c_void_p)
		self.lib.ffishim_bidirectional_init_customer.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_customer_generate_proof.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_customer_generate_proof.restype = c_void_p

		self.lib.ffishim_bidirectional_generate_channel_id.argtypes = (c_void_p, )
		self.lib.ffishim_bidirectional_generate_channel_id.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_merchant_issue_close_token.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_merchant_issue_close_token.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_merchant_issue_pay_token.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_merchant_issue_pay_token.restype = c_void_p

		self.lib.ffishim_bidirectional_verify_close_token.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_verify_close_token.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_customer_final.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_customer_final.restype = c_void_p

		# PAY PROTOCOL

		self.lib.ffishim_bidirectional_pay_generate_payment_proof.argtypes = (c_void_p, c_void_p, ctypes.c_int32)
		self.lib.ffishim_bidirectional_pay_generate_payment_proof.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_payment_proof.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_payment_proof.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_multiple_payment_proofs.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_multiple_payment_proofs.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_generate_revoke_token.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_generate_revoke_token.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_revoke_token.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_revoke_token.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_multiple_revoke_tokens.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_multiple_revoke_tokens.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_payment_token.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_payment_token.restype = c_void_p

		# CLOSE

		self.lib.ffishim_bidirectional_customer_close.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_customer_close.restype = c_void_p

		self.lib.ffishim_bidirectional_merchant_close.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_merchant_close.restype = c_void_p

		# ON-CHAIN BOLT LOGIC / WTPs

		self.lib.ffishim_bidirectional_wtp_verify_cust_close_message.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_wtp_verify_cust_close_message.restype = c_void_p

		self.lib.ffishim_bidirectional_wtp_verify_merch_close_message.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_wtp_verify_merch_close_message.restype = c_void_p

		self.lib.ffishim_free_string.argtypes = (c_void_p, )

	def channel_setup(self, name, third_party_support=0):
		output_string = self.lib.ffishim_bidirectional_channel_setup(name.encode(), third_party_support)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('channel_state')

	# INIT PROTOCOL

	def bidirectional_init_merchant(self, channel_state, name):
		output_string = self.lib.ffishim_bidirectional_init_merchant(channel_state.encode(), name.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('channel_token'), output_dictionary.get('merch_state'), output_dictionary.get('channel_state')

	def bidirectional_init_customer(self, channel_token, b0_cust, b0_merch, name):
		output_string = self.lib.ffishim_bidirectional_init_customer(channel_token.encode(), b0_cust, b0_merch, name.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('channel_token'), output_dictionary.get('cust_state'))

	# ESTABLISH PROTOCOL

	def bidirectional_generate_channel_id(self, channel_token):
		output_string = self.lib.ffishim_bidirectional_generate_channel_id(channel_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('channel_id')

	def bidirectional_establish_customer_generate_proof(self, channel_token, cust_state):
		output_string = self.lib.ffishim_bidirectional_establish_customer_generate_proof(channel_token.encode(), cust_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('channel_token'), output_dictionary.get('cust_state'), output_dictionary.get('com'), output_dictionary.get('com_proof')

	def bidirectional_establish_merchant_issue_close_token(self, channel_state, com, com_proof, channel_id, init_cust, init_merch, merch_state):
		output_string = self.lib.ffishim_bidirectional_establish_merchant_issue_close_token(channel_state.encode(), com.encode(), com_proof.encode(), json.dumps(channel_id).encode(), init_cust, init_merch, merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('close_token')

	def bidirectional_establish_merchant_issue_pay_token(self, channel_state, com, merch_state):
		output_string = self.lib.ffishim_bidirectional_establish_merchant_issue_pay_token(channel_state.encode(), com.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('pay_token')

	def bidirectional_establish_customer_verify_close_token(self, channel_state, cust_state, close_token):
		output_string = self.lib.ffishim_bidirectional_verify_close_token(channel_state.encode(), cust_state.encode(), close_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		is_token_valid = self._convert_boolean(output_dictionary.get('is_token_valid'))
		return is_token_valid, output_dictionary.get('channel_state'), output_dictionary.get('cust_state')

	def bidirectional_establish_customer_final(self, channel_state, cust_state, pay_token):
		output_string = self.lib.ffishim_bidirectional_establish_customer_final(channel_state.encode(), cust_state.encode(), pay_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		is_established = self._convert_boolean(output_dictionary.get('is_established'))
		return is_established, output_dictionary.get('channel_state'), output_dictionary.get('cust_state')

	# PAY PROTOCOL

	# generate payment proof and new cust state
	def bidirectional_pay_generate_payment_proof(self, channel_state, cust_state, amount):
		output_string = self.lib.ffishim_bidirectional_pay_generate_payment_proof(channel_state.encode(), cust_state.encode(), amount)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('payment'), output_dictionary.get('cust_state')

	# verify payment proof
	def bidirectional_pay_verify_payment_proof(self, channel_state, pay_proof, merch_state):
		output_string = self.lib.ffishim_bidirectional_pay_verify_payment_proof(channel_state.encode(), pay_proof.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('close_token'), output_dictionary.get('merch_state'))

	# verify multiple payment proof
	def bidirectional_pay_verify_multiple_payment_proofs(self, channel_state, sender_pay_proof, receiver_pay_proof, merch_state):
		output_string = self.lib.ffishim_bidirectional_pay_verify_multiple_payment_proofs(channel_state.encode(), sender_pay_proof.encode(), receiver_pay_proof.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('sender_close_token'), output_dictionary.get('receiver_cond_close_token'), output_dictionary.get('merch_state'))

	# generate revoke token
	def bidirectional_pay_generate_revoke_token(self, channel_state, cust_state, new_cust_state, close_token):
		output_string = self.lib.ffishim_bidirectional_pay_generate_revoke_token(channel_state.encode(), cust_state.encode(),
																				 new_cust_state.encode(), close_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('revoke_token'), output_dictionary.get('cust_state')

	# verify revoke token
	def bidirectional_pay_verify_revoke_token(self, revoke_token, merch_state):
		output_string = self.lib.ffishim_bidirectional_pay_verify_revoke_token(revoke_token.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('pay_token'), output_dictionary.get('merch_state'))

	# verify multiple revoke tokens
	def bidirectional_pay_verify_multiple_revoke_tokens(self, sender_revoke_token, receiver_revoke_token, merch_state):
		output_string = self.lib.ffishim_bidirectional_pay_verify_multiple_revoke_tokens(sender_revoke_token.encode(), receiver_revoke_token.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('sender_pay_token'), output_dictionary.get('receiver_pay_token'), output_dictionary.get('merch_state'))

	# verify payment token
	def bidirectional_pay_verify_payment_token(self, channel_state, cust_state, pay_token):
		output_string = self.lib.ffishim_bidirectional_pay_verify_payment_token(channel_state.encode(), cust_state.encode(), pay_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		is_pay_valid = self._convert_boolean(output_dictionary.get('is_pay_valid'))
		return (output_dictionary.get('cust_state'), is_pay_valid)

	# CLOSE

	def bidirectional_customer_close(self, channel_state, cust_state):
		output_string = self.lib.ffishim_bidirectional_customer_close(channel_state.encode(), cust_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('cust_close')

	def bidirectional_merchant_close(self, channel_state, channel_token, address, cust_close, merch_state):
		output_string = self.lib.ffishim_bidirectional_merchant_close(channel_state.encode(), channel_token.encode(),
																	  address.encode(), cust_close.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('wpk'), output_dictionary.get('merch_close'), output_dictionary.get('error'))

	# WTP logic

	def wtp_get_wallet(self, cust_state):
		cust_state_dict = self._interperate_json_string_as_dictionary(cust_state)
		return json.dumps(cust_state_dict.get("wpk")), json.dumps(cust_state_dict.get("wallet"))

	def wtp_get_close_token(self, cust_close):
		cust_close_dict = self._interperate_json_string_as_dictionary(cust_close)
		return json.dumps(cust_close_dict.get("signature"))

	def wtp_verify_cust_close_message(self, channel_token, wpk, cust_close_wallet, close_token):
		output_string = self.lib.ffishim_bidirectional_wtp_verify_cust_close_message(channel_token.encode(),
																				 wpk.encode(),
																				 cust_close_wallet.encode(),
																				 close_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('result')

	def wtp_verify_merch_close_message(self, channel_token, wpk, merch_close):
		output_string = self.lib.ffishim_bidirectional_wtp_verify_merch_close_message(channel_token.encode(),
																					  wpk.encode(),
																					  merch_close.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('result')

	def _interperate_json_string_as_dictionary(self, json_string):
		return ast.literal_eval(json_string)

	def _convert_boolean(self, bool_str):
		if bool_str == "true":
			return True
		if bool_str == "false":
			return False
		return bool_str

if platform == 'darwin':
	prefix = 'lib'
	ext = 'dylib'
elif platform == 'win32':
	prefix = ''
	ext = 'dll'
else:
	prefix = 'lib'
	ext = 'so'

DEBUG = 'debug'
RELEASE = 'release'
mode = RELEASE # debug or release

def run_unit_test():
	libbolt = Libbolt('target/{}/{}bolt.{}'.format(mode, prefix, ext))

	b0_cust = 100
	b0_merch = 10

	channel_state = libbolt.channel_setup("My New Channel A")

	print("channel state new: ", len(channel_state))

	(channel_token, merch_state, channel_state) = libbolt.bidirectional_init_merchant(channel_state, "Bob")

	print("merch_state: ", len(merch_state))
	#print("channel_token: ", type(_channel_token))

	(channel_token, cust_state) = libbolt.bidirectional_init_customer(channel_token, b0_cust, b0_merch, "Alice")
	print("cust_state: ", len(cust_state))

	(channel_token, cust_state, com, com_proof) = libbolt.bidirectional_establish_customer_generate_proof(channel_token, cust_state)
	print("channel token: => ", channel_token)
	print("com: ", com)

	cust_state_dict = json.loads(cust_state)
	channel_id = libbolt.bidirectional_generate_channel_id(channel_token)
	print("channel ID: ", channel_id)
	#print("wallet chan ID: ", cust_state_dict["wallet"]["channelId"])

	close_token = libbolt.bidirectional_establish_merchant_issue_close_token(channel_state, com, com_proof, cust_state_dict["wallet"]["channelId"], b0_cust, b0_merch, merch_state)
	print("close token: ", close_token)

	(is_token_valid, channel_state, cust_state) = libbolt.bidirectional_establish_customer_verify_close_token(channel_state, cust_state, close_token)

	pay_token = libbolt.bidirectional_establish_merchant_issue_pay_token(channel_state, com, merch_state)
	print("pay token: ", pay_token)

	(is_channel_established, channel_state, cust_state) = libbolt.bidirectional_establish_customer_final(channel_state, cust_state, pay_token)
	if is_channel_established:
		print("updated cust_state: ", cust_state)
	else:
		print("channel still not established. did you verify close token?")

	# Pay protocol
	print("Pay protocol...")

	# make a payment
	amount = 5
	(payment_proof, new_cust_state) = libbolt.bidirectional_pay_generate_payment_proof(channel_state, cust_state, amount)
	print("Pay proof: ", len(payment_proof))
	print("new cust wallet: ", new_cust_state)
	print("<========================================>")
	revoked_wpk, _ = libbolt.wtp_get_wallet(new_cust_state)

	(new_close_token, merch_state) = libbolt.bidirectional_pay_verify_payment_proof(channel_state, payment_proof, merch_state)
	print("Close token: ", new_close_token)
	print("<========================================>")

	(revoke_token, cust_state) = libbolt.bidirectional_pay_generate_revoke_token(channel_state, cust_state, new_cust_state, new_close_token)
	print("Revoke token: ", revoke_token)

	(pay_token, merch_state) = libbolt.bidirectional_pay_verify_revoke_token(revoke_token, merch_state)
	print("Pay token: ", pay_token)

	(cust_state, is_pay_valid) = libbolt.bidirectional_pay_verify_payment_token(channel_state, cust_state, pay_token)
	print("Pay token is valid: ", is_pay_valid)

	old_cust_close = libbolt.bidirectional_customer_close(channel_state, cust_state)

	# make a payment
	amount = 10
	(payment_proof2, new_cust_state2) = libbolt.bidirectional_pay_generate_payment_proof(channel_state, cust_state, amount)
	print("Pay proof 2: ", len(payment_proof2))
	print("new cust wallet 2: ", new_cust_state2)
	print("<========================================>")

	(new_close_token2, merch_state) = libbolt.bidirectional_pay_verify_payment_proof(channel_state, payment_proof2, merch_state)
	print("Close token 2: ", new_close_token2)
	print("<========================================>")

	(revoke_token2, cust_state) = libbolt.bidirectional_pay_generate_revoke_token(channel_state, cust_state, new_cust_state2, new_close_token2)
	print("Revoke token 2: ", revoke_token)

	(pay_token2, merch_state) = libbolt.bidirectional_pay_verify_revoke_token(revoke_token2, merch_state)
	print("Pay token 2: ", pay_token2)

	(cust_state, is_pay_valid) = libbolt.bidirectional_pay_verify_payment_token(channel_state, cust_state, pay_token2)
	print("Pay token is valid: ", is_pay_valid)

	print("<========================================>")
	print("<========================================>")

	cust_close = libbolt.bidirectional_customer_close(channel_state, cust_state)
	print("Cust close msg: ", cust_close)
	print("<========================================>")

	# normal case: no action b/c cust close is valid
	address = "11" * 32
	merch_close = libbolt.bidirectional_merchant_close(channel_state, channel_token, address, cust_close, merch_state)
	print("Customer initiated - Merch close msg: ", merch_close)
	print("<========================================>")

	# common case: merchant catches customer double spending
	address = "11" * 32
	merch_wpk, merch_close_msg, _ = libbolt.bidirectional_merchant_close(channel_state, channel_token, address, old_cust_close, merch_state)
	print("Double spend - Merch close msg: ", merch_close_msg)
	merch_close_valid = libbolt.wtp_verify_merch_close_message(channel_token, merch_wpk, merch_close_msg)
	print("Merchant close msg valid: ", merch_close_valid)
	print("<========================================>")

	print("<========================================>")
	wpk, cust_close_wallet = libbolt.wtp_get_wallet(cust_state)
	print("wpk = ", wpk)
	print("close-msg wallet = ", cust_close_wallet)
	cust_close_token = libbolt.wtp_get_close_token(cust_close)
	print("close token: ", cust_close_token)
	print("Valid channel opening: ", libbolt.wtp_verify_cust_close_message(channel_token, wpk, cust_close_wallet, cust_close_token))
	# TODO: merch close when cust_close represents correct channel state

	print("Invalid channel opening: ", libbolt.wtp_verify_cust_close_message(channel_token, revoked_wpk, cust_close_wallet, cust_close_token))
	print("<========================================>")

if __name__ == "__main__":
	run_unit_test()
