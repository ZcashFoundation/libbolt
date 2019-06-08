from ctypes import cdll
from sys import platform

import sys, ctypes
from ctypes import c_void_p, c_uint8

import ast
import json

class Libbolt(object):
	"""docstring for Libbolt"""

	def __init__(self, path):
		self.lib = cdll.LoadLibrary(path)
		self.load_library_params()

	def load_library_params(self):
		self.lib.ffishim_bidirectional_setup.argtypes = (c_uint8, )
		self.lib.ffishim_bidirectional_setup.restype = c_void_p

		self.lib.ffishim_bidirectional_channelstate_new.argtypes = (c_void_p, c_uint8)
		self.lib.ffishim_bidirectional_channelstate_new.restype = c_void_p

		self.lib.ffishim_bidirectional_keygen.argtypes = (c_void_p, )
		self.lib.ffishim_bidirectional_keygen.restype = c_void_p

		self.lib.ffishim_bidirectional_init_merchant.argtypes = (c_void_p, c_uint8, c_void_p)
		self.lib.ffishim_bidirectional_init_merchant.restype = c_void_p

		self.lib.ffishim_bidirectional_generate_commit_setup.argtypes = (c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_generate_commit_setup.restype = c_void_p

		self.lib.ffishim_bidirectional_init_customer.argtypes = (c_void_p, c_void_p, ctypes.c_int32, ctypes.c_int32, c_void_p, c_void_p )
		self.lib.ffishim_bidirectional_init_customer.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_customer_phase1.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_customer_phase1.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_merchant_phase2.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_merchant_phase2.restype = c_void_p

		self.lib.ffishim_bidirectional_establish_customer_final.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_establish_customer_final.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_by_customer_phase1_precompute.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_by_customer_phase1_precompute.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_by_customer_phase1.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, ctypes.c_int32)
		self.lib.ffishim_bidirectional_pay_by_customer_phase1.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_by_merchant_phase1.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_by_merchant_phase1.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_by_customer_phase2.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_by_customer_phase2.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_by_merchant_phase2.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_by_merchant_phase2.restype = c_void_p

		self.lib.ffishim_bidirectional_pay_by_customer_final.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_pay_by_customer_final.restype = c_void_p

		self.lib.ffishim_bidirectional_customer_refund.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_customer_refund.restype = c_void_p

		self.lib.ffishim_bidirectional_merchant_refund.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_merchant_refund.restype = c_void_p

		self.lib.ffishim_bidirectional_resolve.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_bidirectional_resolve.restype = c_void_p

		# Exposing the decommitment functionality
		self.lib.ffishim_commit_scheme_decommit.argtypes = (c_void_p, c_void_p, c_void_p)
		self.lib.ffishim_commit_scheme_decommit.restype = c_void_p

		# Things that don't really work

		self.lib.ffishim_free_string.argtypes = (c_void_p, )


	def bidirectional_setup(self, extra_verify):
		inputs = 0
		if extra_verify:
			inputs = 1
		output_string = ast.literal_eval(ctypes.cast(self.lib.ffishim_bidirectional_setup(inputs), ctypes.c_char_p).value.decode('utf-8'))
		return output_string['pp']

	def bidirectional_keygen(self, pp):
		output_string = self.lib.ffishim_bidirectional_keygen(pp.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['keypair']

	def bidirectional_channelstate_new(self, name, third_party_support):
		output_string = self.lib.ffishim_bidirectional_channelstate_new(name.encode(), third_party_support)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['state']

	def bidirectional_init_merchant(self, pp, b0_cust, merch_keys):
		output_string = self.lib.ffishim_bidirectional_init_merchant(pp.encode(), b0_cust, merch_keys.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['merchant_data']

	def bidirectional_generate_commit_setup(self, pp, merch_public_key):
		output_string = self.lib.ffishim_bidirectional_generate_commit_setup(pp.encode(), merch_public_key.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['commit_setup']

	def bidirectional_init_customer(self, pp, channel, b0_cust, b0_merch, cm_csp, cust_keys):
		output_string = self.lib.ffishim_bidirectional_init_customer(pp.encode(), channel.encode(), b0_cust, b0_merch, cm_csp.encode(), cust_keys.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['customer_data'], output_dictionary['state'])

	def bidirectional_establish_customer_phase1(self, pp, cust_data, merch_data): # TODO merch_data.bases should be parsed out.
		output_string = self.lib.ffishim_bidirectional_establish_customer_phase1(pp.encode(), cust_data.encode(), merch_data.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['proof']

	def bidirectional_establish_merchant_phase2(self, pp, channel, merch_data, proof1):
		output_string = self.lib.ffishim_bidirectional_establish_merchant_phase2(pp.encode(), channel.encode(), merch_data.encode(), proof1.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['wallet_sig'], output_dictionary['state'])

	def bidirectional_establish_customer_final(self, pp, merch_pubkey, cust_data, wallet_sig):
		output_string = self.lib.ffishim_bidirectional_establish_customer_final(pp.encode(), merch_pubkey.encode(), cust_data.encode(), wallet_sig.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['customer_data']

	def bidirectional_pay_by_customer_phase1_precompute(self, pp, cust_data, merch_pubkey):
		output_string = self.lib.ffishim_bidirectional_pay_by_customer_phase1_precompute(pp.encode(), cust_data.encode(), merch_pubkey.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['customer_data']

	def bidirectional_pay_by_customer_phase1(self, pp, channel, cust_data, merch_public_key, balance_increment):
		output_string = self.lib.ffishim_bidirectional_pay_by_customer_phase1(pp.encode(), channel.encode(), cust_data.encode(), merch_public_key.encode(), balance_increment)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['channel_token'],output_dictionary['new_wallet'],output_dictionary['pay_proof'] )

	def bidirectional_pay_by_merchant_phase1(self, pp, channel, pay_proof, merch_data):
		output_string = self.lib.ffishim_bidirectional_pay_by_merchant_phase1(pp.encode(), channel.encode(), pay_proof.encode(), merch_data.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['rt_w'],output_dictionary['state'])

	def bidirectional_pay_by_customer_phase2(self, pp, cust_data, new_wallet, merch_public_key, rt_w):
		output_string = self.lib.ffishim_bidirectional_pay_by_customer_phase2(pp.encode(), cust_data.encode(), new_wallet.encode(), merch_public_key.encode(), rt_w.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['rv_w']

	def bidirectional_pay_by_merchant_phase2(self, pp, channel, pay_proof, merch_data, revoke_token):
		output_string = self.lib.ffishim_bidirectional_pay_by_merchant_phase2( pp.encode(), channel.encode(), pay_proof.encode(), merch_data.encode(), revoke_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['new_wallet_sig'],output_dictionary['state'], output_dictionary['merch_data'])

	def bidirectional_pay_by_customer_final(self, pp, merch_public_key, cust_data, channel_token, new_wallet, refund_token, new_wallet_sig):
		output_string = self.lib.ffishim_bidirectional_pay_by_customer_final(pp.encode(), merch_public_key.encode(), cust_data.encode(), channel_token.encode(),
																			 new_wallet.encode(), refund_token.encode(), new_wallet_sig.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['customer_data']

	def bidirectional_customer_refund(self, pp, channel, merch_public_key, wallet):
		output_string = self.lib.ffishim_bidirectional_customer_refund(pp.encode(), channel.encode(), merch_public_key.encode(), wallet.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['rc_c']

	def bidirectional_merchant_refund(self, pp, channel, channel_token, merch_data, channel_closure, revoke_token):
		output_string = self.lib.ffishim_bidirectional_merchant_refund(pp.encode(), channel.encode(), channel_token.encode(), merch_data.encode(), channel_closure.encode(), revoke_token.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (output_dictionary['rc_m'], output_dictionary['state'])

	def bidirectional_resolve(self, pp, cust_data, merch_data, cust_closure, merch_closure):
		output_string = self.lib.ffishim_bidirectional_resolve( pp.encode(), cust_data.encode(), merch_data.encode(), cust_closure.encode(), merch_closure.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return (int(output_dictionary['new_b0_cust']), int(output_dictionary['new_b0_merch']))

# --------------------------------------------
	def commit_scheme_decommit(self, csp, commitment, x):
		output_string = self.lib.ffishim_commit_scheme_decommit(csp.encode(), commitment.encode(), x.encode())
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		if output_dictionary['return_value'] == 'true':
			return True
		return False

	def interperate_json_string_as_dictionary(self, json_string):
		return ast.literal_eval(json_string)

	def util_convert_int_list_to_hex_string(self, dictionary):
		return "".join(["{0:02x}".format(x) for x in dictionary])

	def util_extract_public_key_from_keypair(self, keypair):
		# Interperate the input keypair struct as a dictionary and then extract
		dictionary = self.interperate_json_string_as_dictionary(keypair)
		return json.dumps(dictionary['pk'])

	def util_extract_pub_bases_from_keypair(self, keypair):
		dictionary = self.interperate_json_string_as_dictionary(keypair)
		return json.dumps(dictionary['bases'])

if platform == 'darwin':
    prefix = 'lib'
    ext = 'dylib'
elif platform == 'win32':
    prefix = ''
    ext = 'dll'
else:
    prefix = 'lib'
    ext = 'so'

releaseordebug = 'debug'

libbolt = Libbolt('target/{}/{}bolt.{}'.format(releaseordebug, prefix, ext))

b0_cust = 50
b0_merch = 50

pp = libbolt.bidirectional_setup(False)

merch_keys = libbolt.bidirectional_keygen(pp)

cust_keys = libbolt.bidirectional_keygen(pp)

channel_state = libbolt.bidirectional_channelstate_new("My New Channel A", 0)

merch_data = libbolt.bidirectional_init_merchant(pp, b0_cust, merch_keys)

cm_csp = libbolt.bidirectional_generate_commit_setup(pp, libbolt.util_extract_public_key_from_keypair(merch_keys))

cust_data, channel_state = libbolt.bidirectional_init_customer(pp, channel_state, b0_cust, b0_merch, cm_csp, cust_keys)

merch_bases = libbolt.util_extract_pub_bases_from_keypair(merch_data)
proof1 = libbolt.bidirectional_establish_customer_phase1(pp, cust_data, merch_bases)
print("proof 1: ", proof1)

wallet_sig, channel_state = libbolt.bidirectional_establish_merchant_phase2(pp, channel_state, merch_data, proof1)

cust_data = libbolt.bidirectional_establish_customer_final(pp, libbolt.util_extract_public_key_from_keypair(merch_keys), cust_data, wallet_sig)

cust_data = libbolt.bidirectional_pay_by_customer_phase1_precompute(pp, cust_data, libbolt.util_extract_public_key_from_keypair(merch_keys))

(channel_token, new_wallet, pay_proof) = libbolt.bidirectional_pay_by_customer_phase1(pp, channel_state, cust_data, libbolt.util_extract_public_key_from_keypair(merch_keys), 5)

(rt_w, channel_state) =  libbolt.bidirectional_pay_by_merchant_phase1(pp, channel_state, pay_proof, merch_data)

rv_w = libbolt.bidirectional_pay_by_customer_phase2(pp, cust_data, new_wallet, libbolt.util_extract_public_key_from_keypair(merch_keys), rt_w)

(new_wallet_sig, state, merch_data)	= libbolt.bidirectional_pay_by_merchant_phase2(pp, channel_state, pay_proof, merch_data, rv_w)

cust_data = libbolt.bidirectional_pay_by_customer_final(pp, libbolt.util_extract_public_key_from_keypair(merch_keys), cust_data, channel_token, new_wallet, rt_w, new_wallet_sig)

print("--------------------")

cust_data = libbolt.bidirectional_pay_by_customer_phase1_precompute(pp, cust_data, libbolt.util_extract_public_key_from_keypair(merch_keys))

(channel_token, new_wallet, pay_proof) = libbolt.bidirectional_pay_by_customer_phase1(pp, channel_state, cust_data, libbolt.util_extract_public_key_from_keypair(merch_keys), -10)

# temp fix re: T/F from Rust -> C/Py
channel_token = channel_token.replace('false', 'False')
Tc = libbolt.interperate_json_string_as_dictionary(channel_token)
#print(Tc)
w_com_c = libbolt.util_convert_int_list_to_hex_string(Tc["w_com"]["c"])
w_com_r = libbolt.util_convert_int_list_to_hex_string(Tc["w_com"]["r"])

print("w_com.c => 0x{}, len = {}".format(w_com_c, len(Tc["w_com"]["c"])))
print("w_com.r => 0x{}, len = {}".format(w_com_r, len(Tc["w_com"]["r"])))
print("--------------------")

# TODO: compute hash of the channel pubkey?

# write out the CSP bytes
csp = libbolt.interperate_json_string_as_dictionary(cm_csp)
total_csp = ""
for i in range(0, len(csp["pub_bases"])):
    csp_hex = libbolt.util_convert_int_list_to_hex_string(csp["pub_bases"][i])
    print("csp[{}] => 0x{}, len = {}".format(i, csp_hex, len(csp["pub_bases"][i])))
    total_csp += csp_hex

print("CSP Blob = ", total_csp)
print("Overall len = {}".format(len(total_csp)/2))


