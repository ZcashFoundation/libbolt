from ctypes import cdll
from sys import platform

import sys, ctypes
from ctypes import c_void_p, c_uint8

if platform == 'darwin':
    prefix = 'lib'
    ext = 'dylib'
elif platform == 'win32':
    prefix = ''
    ext = 'dll'
else:
    prefix = 'lib'
    ext = 'so'


libbolt = cdll.LoadLibrary('target/debug/{}libboltlib.{}'.format(prefix, ext))

libbolt.ffishim_bidirectional_setup.argtypes = (c_uint8, )
libbolt.ffishim_bidirectional_setup.restype = c_void_p

libbolt.ffishim_bidirectional_channelstate_new.argtypes = (c_void_p, c_uint8)
libbolt.ffishim_bidirectional_channelstate_new.restype = c_void_p

libbolt.ffishim_bidirectional_keygen.argtypes = (c_void_p, )
libbolt.ffishim_bidirectional_keygen.restype = c_void_p

libbolt.ffishim_bidirectional_init_merchant.argtypes = (c_void_p, c_uint8, c_void_p)
libbolt.ffishim_bidirectional_init_merchant.restype = c_void_p

libbolt.ffishim_bidirectional_generate_commit_setup.argtypes = (c_void_p, c_void_p)
libbolt.ffishim_bidirectional_generate_commit_setup.restype = c_void_p

libbolt.ffishim_bidirectional_init_customer.argtypes = (c_void_p, c_void_p, ctypes.c_int32, ctypes.c_int32, c_void_p, c_void_p )
libbolt.ffishim_bidirectional_init_customer.restype = c_void_p

libbolt.ffishim_bidirectional_establish_customer_phase1.argtypes = (c_void_p, c_void_p, c_void_p)
libbolt.ffishim_bidirectional_establish_customer_phase1.restype = c_void_p

libbolt.ffishim_bidirectional_establish_merchant_phase2.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
libbolt.ffishim_bidirectional_establish_merchant_phase2.restype = c_void_p

libbolt.ffishim_bidirectional_establish_customer_final.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
libbolt.ffishim_bidirectional_establish_customer_final.restype = c_uint8


bidirectional_setup  =  libbolt.ffishim_bidirectional_setup
bidirectional_channelstate_new  =  libbolt.ffishim_bidirectional_channelstate_new
bidirectional_keygen  =  libbolt.ffishim_bidirectional_keygen
bidirectional_init_merchant  =  libbolt.ffishim_bidirectional_init_merchant
bidirectional_generate_commit_setup  =  libbolt.ffishim_bidirectional_generate_commit_setup
bidirectional_init_customer  =  libbolt.ffishim_bidirectional_init_customer
bidirectional_establish_customer_phase1  =  libbolt.ffishim_bidirectional_establish_customer_phase1
bidirectional_establish_merchant_phase2  =  libbolt.ffishim_bidirectional_establish_merchant_phase2
bidirectional_establish_customer_final  =  libbolt.ffishim_bidirectional_establish_customer_final

b0_cust = 50;
b0_merch = 50;

pp = bidirectional_setup(0)

merch_keys = bidirectional_keygen(pp)
print(" After merch_keys") 
cust_keys = bidirectional_keygen(pp)
print(" After cust_keys")
channel = bidirectional_channelstate_new("My New Channel A", 0)
print(" After channel")
merch_data = bidirectional_init_merchant(pp, b0_cust, merch_keys)
print(" After merch_data")
cm_csp = bidirectional_generate_commit_setup(pp, merch_keys)
print(" After cm_csp")
cust_data = bidirectional_init_customer(pp, channel, b0_cust, b0_merch, cm_csp, cust_keys)
print(" After cust_data")
proof1 = bidirectional_establish_customer_phase1(pp, cust_data, merch_data)
print(" After proof1")
wallet_sig = bidirectional_establish_merchant_phase2(pp, channel, merch_data, proof1)
print(" After wallet_sig")
setup = bidirectional_establish_customer_final(pp, merch_keys, cust_data, wallet_sig)
print(" After setup")

print(setup)
print(ctypes.cast(pp, ctypes.c_char_p).value.decode('utf-8'))
print(ctypes.cast(keys, ctypes.c_char_p).value.decode('utf-8'))
print(ctypes.cast(channel_token, ctypes.c_char_p).value.decode('utf-8'))
print(ctypes.cast(commit_setup, ctypes.c_char_p).value.decode('utf-8'))
