from ctypes import cdll
from sys import platform

import sys, ctypes
from ctypes import c_void_p, c_uint8

import ast
import json

class Libbolt(object):

	# bidirectional_setup  =  libbolt.ffishim_bidirectional_setup
# bidirectional_channelstate_new  =  libbolt.ffishim_bidirectional_channelstate_new
# bidirectional_keygen  =  libbolt.ffishim_bidirectional_keygen
# bidirectional_init_merchant  =  libbolt.ffishim_bidirectional_init_merchant
# bidirectional_generate_commit_setup  =  libbolt.ffishim_bidirectional_generate_commit_setup
# bidirectional_init_customer  =  libbolt.ffishim_bidirectional_init_customer
# bidirectional_establish_customer_phase1  =  libbolt.ffishim_bidirectional_establish_customer_phase1
# bidirectional_establish_merchant_phase2  =  libbolt.ffishim_bidirectional_establish_merchant_phase2
# bidirectional_establish_customer_final  =  libbolt.ffishim_bidirectional_establish_customer_final

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
		self.lib.ffishim_bidirectional_establish_customer_final.restype = c_uint8

		# For Test Structures ONLY

		# libbolt.ffishim_bidirectional_teststruct.argtypes = (c_uint8, )
		self.lib.ffishim_bidirectional_teststruct.restype = c_void_p

		self.lib.ffishim_bidirectional_teststruct_in.argtypes = (c_void_p, )
		self.lib.ffishim_bidirectional_teststruct_in.restype = c_uint8

		self.lib.ffishim_free_string.argtypes = (c_void_p, )

			# bidirectional_teststruct = libbolt.ffishim_bidirectional_teststruct
			# bidirectional_teststruct_in = libbolt.ffishim_bidirectional_teststruct_in

		# TODO set all the dictionary keys iin one place instead of hard coding them

	def bidirectional_teststruct(self):
		output_string = ast.literal_eval(ctypes.cast(self.lib.ffishim_bidirectional_teststruct(), ctypes.c_char_p).value.decode('utf-8'))
		print(output_string)
		return output_string['a']

	def bidirectional_teststruct_in(self, input_struct):	
		return self.lib.ffishim_bidirectional_teststruct_in(input_struct)

	def bidirectional_setup(self, extra_verify):
		inputs = 0
		if extra_verify:
			inputs = 1
		# print(ctypes.cast(self.lib.ffishim_bidirectional_setup(inputs), ctypes.c_char_p).value.decode('utf-8'))
		output_string = ast.literal_eval(ctypes.cast(self.lib.ffishim_bidirectional_setup(inputs), ctypes.c_char_p).value.decode('utf-8'))
		return output_string['pp']

	def bidirectional_keygen(self, pp):
		output_string = self.lib.ffishim_bidirectional_keygen(pp)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['keypair']

	def bidirectional_channelstate_new(self, name, third_party_support):
		output_string = self.lib.ffishim_bidirectional_channelstate_new(name, third_party_support)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['state']

	def bidirectional_init_merchant(self, pp, b0_cust, merch_keys):
		output_string = self.lib.ffishim_bidirectional_init_merchant(pp, b0_cust, merch_keys)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['merchant_data']

	def bidirectional_generate_commit_setup(self, pp, merch_public_key):
		output_string = self.lib.ffishim_bidirectional_generate_commit_setup(pp, merch_public_key)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		return output_dictionary['commit_setup']

	def bidirectional_init_customer(self, pp, channel, b0_cust, b0_merch, cm_csp, cust_keys):
		output_string = self.lib.ffishim_bidirectional_init_customer(pp, channel, b0_cust, b0_merch, cm_csp, cust_keys)
		output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
		# self.lib.ffishim_free_string(channel) //TODO THIS THROWS AN ERROR?!?!?!??!!
		return (output_dictionary['customer_data'], output_dictionary['state'])

	# def bidirectional_establish_customer_phase1(self, pp, cust_data, merch_data): # TODO merch_data.bases should be parsed out.
	# 	output_string = self.lib.ffishim_bidirectional_establish_customer_phase1(pp, cust_data, merch_data)
	# 	output_dictionary = ast.literal_eval(ctypes.cast(output_string, ctypes.c_char_p).value.decode('utf-8'))
	# 	return output_dictionary['proof']



# --------------------------------------------

	def util_extract_public_key_from_keypair(self, keypair):
		# Interperate the input keypair struct as a dictionary and then extract
		dictionary = ast.literal_eval(keypair)
		return json.dumps(dictionary['pk'])


if platform == 'darwin':
    prefix = 'lib'
    ext = 'dylib'
elif platform == 'win32':
    prefix = ''
    ext = 'dll'
else:
    prefix = 'lib'
    ext = 'so'

libbolt = Libbolt('target/debug/{}bolt.{}'.format(prefix, ext))


# print(a)

# b = libbolt.bidirectional_teststruct_in(a)

# print(b)
# print(second_thing['range_proof_bits'])

# print(ctypes.cast(a, ctypes.c_char_p).value.decode('utf-8'))
# print(ctypes.cast(b, ctypes.c_char_p).value.decode('utf-8'))


b0_cust = 50;
b0_merch = 50;

pp = libbolt.bidirectional_setup(False)
# print(pp)

merch_keys = libbolt.bidirectional_keygen(pp)
# print merch_keys
cust_keys = libbolt.bidirectional_keygen(pp)
# print(cust_keys)

channel_state = libbolt.bidirectional_channelstate_new("My New Channel A", 0)
# print(channel)
# print(" After channel")
merch_data = libbolt.bidirectional_init_merchant(pp, b0_cust, merch_keys)
# print(merch_data)
# print(" After merch_data")
cm_csp = libbolt.bidirectional_generate_commit_setup(pp, libbolt.util_extract_public_key_from_keypair(merch_keys))
# print(" After cm_csp")
cust_data, channel_state = libbolt.bidirectional_init_customer(pp, channel_state, b0_cust, b0_merch, cm_csp, cust_keys)
# print channel_state
# print(" After cust_data")
# proof1 = libbolt.bidirectional_establish_customer_phase1(pp, cust_data, merch_data)
# print(" After proof1")
# wallet_sig = bidirectional_establish_merchant_phase2(pp, channel, merch_data, proof1)
# print(" After wallet_sig")
# setup = bidirectional_establish_customer_final(pp, merch_keys, cust_data, wallet_sig)
# print(" After setup")

# print(setup)
# print(ctypes.cast(pp, ctypes.c_char_p).value.decode('utf-8'))
# print(ctypes.cast(keys, ctypes.c_char_p).value.decode('utf-8'))
# print(ctypes.cast(channel_token, ctypes.c_char_p).value.decode('utf-8'))
# print(ctypes.cast(commit_setup, ctypes.c_char_p).value.decode('utf-8'))
