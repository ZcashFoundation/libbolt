from ctypes import cdll
from sys import platform

import sys, ctypes
from ctypes import c_void_p, c_uint8

import ast
import json

class Libbolt(object):
	"""docstring for Libbolt C API"""

	def __init__(self, path):
		self.lib = cdll.LoadLibrary(path)
		self.load_library_params()

	def load_library_params(self):
		self.lib.ffishim_bidirectional_channel_setup.argtypes = (c_void_p, c_uint8)
		self.lib.ffishim_bidirectional_channel_setup.restype = c_void_p

		# ESTABLISH PROTOCOL

		self.lib.ffishim_bidirectional_init_merchant.argtypes = (c_void_p, ctypes.c_int32, c_void_p)
		self.lib.ffishim_bidirectional_init_merchant.restype = c_void_p

		self.lib.ffishim_bidirectional_init_customer.argtypes = (c_void_p, c_void_p, ctypes.c_int32, ctypes.c_int32, c_void_p)
		self.lib.ffishim_bidirectional_init_customer.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_customer_generate_proof.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_customer_generate_proof.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_merchant_issue_close_token.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
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

		self.lib.ffishim_bidirectional_pay_generate_revoke_token.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_generate_revoke_token.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_revoke_token.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_revoke_token.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_verify_payment_token.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_verify_payment_token.restype = c_void_p

		# CLOSE

		self.lib.ffishim_bidirectional_customer_close.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_customer_close.restype = c_void_p

		self.lib.ffishim_bidirectional_merchant_close.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_merchant_close.restype = c_void_p

		# ON-CHAIN BOLT LOGIC / WTPs

		self.lib.ffishim_bidirectional_verify_open_channel.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_verify_open_channel.restype = c_void_p

		#self.lib.ffishim_bidirectional_verify_close_channel.argtypes = (c_void_p, c_void_p)
		#self.lib.ffishim_bidirectional_verify_close_channel.restype = c_void_p

		# self.lib.ffishim_bidirectional_resolve.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		# self.lib.ffishim_bidirectional_resolve.restype = c_void_p

		self.lib.ffishim_free_string.argtypes = (c_void_p, )

	def channel_setup(self, name, third_party_support=0):
		output_string = self.lib.ffishim_bidirectional_channel_setup(name.encode(), third_party_support)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['channel_state']

	# INIT PROTOCOL

	def bidirectional_init_merchant(self, channel_state, b0_merch, name):
		output_string = self.lib.ffishim_bidirectional_init_merchant(channel_state.encode(), b0_merch, name.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['channel_token'], output_dictionary['merch_state']

	def bidirectional_init_customer(self, channel_state, channel_token, b0_cust, b0_merch, name):
		output_string = self.lib.ffishim_bidirectional_init_customer(channel_state.encode(), channel_token.encode(), b0_cust, b0_merch, name.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['channel_token'], output_dictionary['cust_state'])

	# ESTABLISH PROTOCOL

	def bidirectional_establish_customer_generate_proof(self, channel_token, cust_state):
		output_string = self.lib.ffishim_bidirectional_establish_customer_generate_proof(channel_token.encode(), cust_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['channel_token'], output_dictionary['cust_state'], output_dictionary['com'], output_dictionary['com_proof']

	def bidirectional_establish_merchant_issue_close_token(self, channel_state, com, com_proof, merch_state):
		output_string = self.lib.ffishim_bidirectional_establish_merchant_issue_close_token(channel_state.encode(), com.encode(), com_proof.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['close_token']

	def bidirectional_establish_merchant_issue_pay_token(self, channel_state, com, merch_state):
		output_string = self.lib.ffishim_bidirectional_establish_merchant_issue_pay_token(channel_state.encode(), com.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['pay_token']

	def bidirectional_establish_customer_verify_close_token(self, channel_state, cust_state, close_token):
		output_string = self.lib.ffishim_bidirectional_verify_close_token(channel_state.encode(), cust_state.encode(), close_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['is_token_valid'], output_dictionary['channel_state'], output_dictionary['cust_state']

	def bidirectional_establish_customer_final(self, channel_state, cust_state, pay_token):
		output_string = self.lib.ffishim_bidirectional_establish_customer_final(channel_state.encode(), cust_state.encode(), pay_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['is_established'], output_dictionary['channel_state'], output_dictionary['cust_state']

	# PAY PROTOCOL

	# generate payment proof and new cust state
	def bidirectional_pay_generate_payment_proof(self, channel_state, cust_state, amount):
		output_string = self.lib.ffishim_bidirectional_pay_generate_payment_proof(channel_state.encode(), cust_state.encode(), amount)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['payment'], output_dictionary['cust_state']

	# verify payment proof
	def bidirectional_pay_verify_payment_proof(self, channel_state, pay_proof, merch_state):
		output_string = self.lib.ffishim_bidirectional_pay_verify_payment_proof(channel_state.encode(), pay_proof.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['close_token'], output_dictionary['merch_state'])

	# generate revoke token
	def bidirectional_pay_generate_revoke_token(self, channel_state, cust_state, new_cust_state, close_token):
		output_string = self.lib.ffishim_bidirectional_pay_generate_revoke_token(channel_state.encode(), cust_state.encode(),
																				 new_cust_state.encode(), close_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['revoke_token'], output_dictionary['cust_state']

	# verify revoke token
	def bidirectional_pay_verify_revoke_token(self, revoke_token, merch_state):
		output_string = self.lib.ffishim_bidirectional_pay_verify_revoke_token(revoke_token.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['pay_token'], output_dictionary['merch_state'])

	# verify payment token
	def bidirectional_pay_verify_payment_token(self, channel_state, cust_state, pay_token):
		output_string = self.lib.ffishim_bidirectional_pay_verify_payment_token(channel_state.encode(), cust_state.encode(), pay_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['cust_state'], output_dictionary['is_pay_valid'])

	# CLOSE

	def bidirectional_customer_close(self, channel_state, cust_state):
		output_string = self.lib.ffishim_bidirectional_customer_close(channel_state.encode(), cust_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('cust_close')

	def bidirectional_merchant_close(self, channel_state, channel_token, cust_close, merch_state):
		output_string = self.lib.ffishim_bidirectional_merchant_close(channel_state.encode(), channel_token.encode(),
																	  cust_close.encode(), merch_state.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary.get('wpk'), output_dictionary.get('revoke_token'), output_dictionary.get('error'))

	# WTP logic

	def wtp_get_wallet(self, cust_state):
		cust_state_dict = self.interperate_json_string_as_dictionary(cust_state)
		return json.dumps(cust_state_dict.get("wpk")), json.dumps(cust_state_dict.get("wallet"))

	def wtp_get_close_token(self, cust_close):
		cust_close_dict = self.interperate_json_string_as_dictionary(cust_close)
		return json.dumps(cust_close_dict.get("signature"))

	def wtp_verify_open_channel(self, channel_token, wpk, cust_close_wallet, close_token):
		output_string = self.lib.ffishim_bidirectional_verify_open_channel(channel_token.encode(), wpk.encode(), cust_close_wallet.encode(), close_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary.get('result')

# 	def bidirectional_resolve(self, pp, cust_data, merch_data, cust_closure, merch_closure):
# 		output_string = self.lib.ffishim_bidirectional_resolve( pp.encode(), cust_data.encode(), merch_data.encode(), cust_closure.encode(), merch_closure.encode())
# 		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
# 		return (int(output_dictionary['new_b0_cust']), int(output_dictionary['new_b0_merch']))
#
# # --------------------------------------------
# 	def commit_scheme_decommit(self, csp, commitment, x):
# 		output_string = self.lib.ffishim_commit_scheme_decommit(csp.encode(), commitment.encode(), x.encode())
# 		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
# 		if output_dictionary['return_value'] == 'true':
# 			return True
# 		return False

	def interperate_json_string_as_dictionary(self, json_string):
		return ast.literal_eval(json_string)

	def util_convert_int_list_to_hex_string(self, dictionary):
		return "".join(["{0:02x}".format(x) for x in dictionary])

	# def util_extract_public_key_from_keypair(self, keypair):
	# 	# Interperate the input keypair struct as a dictionary and then extract
	# 	dictionary = self.interperate_json_string_as_dictionary(keypair)
	# 	return json.dumps(dictionary['pk'])
	#
	# def util_extract_pub_bases_from_keypair(self, keypair):
	# 	dictionary = self.interperate_json_string_as_dictionary(keypair)
	# 	return json.dumps(dictionary['bases'])

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

	(channel_token, merch_state) = libbolt.bidirectional_init_merchant(channel_state, b0_merch, "Bob")

	print("merch_state: ", len(merch_state))
	#print("channel_token: ", type(_channel_token))

	(channel_token, cust_state) = libbolt.bidirectional_init_customer(channel_state, channel_token, b0_cust, b0_merch, "Alice")
	print("cust_state: ", len(cust_state))

	(channel_token, cust_state, com, com_proof) = libbolt.bidirectional_establish_customer_generate_proof(channel_token, cust_state)
	print("com: ", com)

	close_token = libbolt.bidirectional_establish_merchant_issue_close_token(channel_state, com, com_proof, merch_state)
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

	merch_close_tokens = libbolt.bidirectional_merchant_close(channel_state, channel_token, cust_close, merch_state)
	print("Merch close tokens: ", merch_close_tokens)

	print("<========================================>")
	wpk, cust_close_wallet = libbolt.wtp_get_wallet(cust_state)
	print("wpk = ", wpk)
	print("close-msg wallet = ", cust_close_wallet)
	cust_close_token = libbolt.wtp_get_close_token(cust_close)
	print("close token: ", cust_close_token)
	print("Valid channel opening: ", libbolt.wtp_verify_open_channel(channel_token, wpk, cust_close_wallet, cust_close_token))

	print("Invalid channel opening: ", libbolt.wtp_verify_open_channel(channel_token, revoked_wpk, cust_close_wallet, cust_close_token))

if __name__ == "__main__":
	run_unit_test()
