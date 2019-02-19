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

# lib.getathing.argtypes = (c_uint8, )
# libbolt.ffishim_bidirectional_teststruct.restype = c_void_p

# # lib.freeathing.argtypes = (c_void_p, )

# bi = libbolt.ffishim_bidirectional_teststruct
# a_thing = bi()

# print(ctypes.cast(a_thing, ctypes.c_char_p).value.decode('utf-8'))

# libbolt.ffishim_bidirectional_teststruct_in.argtypes = (c_void_p, )
# libbolt.ffishim_bidirectional_teststruct_in.restype = c_void_p

# infn = libbolt.ffishim_bidirectional_teststruct_in
# a_second_thing = infn(a_thing)


# print(ctypes.cast(a_thing, ctypes.c_char_p).value.decode('utf-8'))


# libbolt.ffishim_bidirectional_setup.argtypes
libbolt.ffishim_bidirectional_setup.restype = c_void_p

libbolt.ffishim_bidirectional_keygen.argtypes = (c_void_p, )
libbolt.ffishim_bidirectional_keygen.restype = c_void_p

libbolt.ffishim_bidirectional_init_merchant.argtypes = (c_void_p, c_uint8, c_void_p)
libbolt.ffishim_bidirectional_init_merchant.restype = c_void_p

libbolt.ffishim_bidirectional_generate_commit_setup.argtypes = (c_void_p, c_void_p)
libbolt.ffishim_bidirectional_generate_commit_setup.restype = c_void_p

bidirectional_setup = libbolt.ffishim_bidirectional_setup

bidirectional_keygen = libbolt.ffishim_bidirectional_keygen

bidirectional_init_merchant = libbolt.ffishim_bidirectional_init_merchant

bidirectional_generate_commit_setup = libbolt.ffishim_bidirectional_generate_commit_setup

pp = bidirectional_setup()

keys = bidirectional_keygen(pp)

channel_token = bidirectional_init_merchant(pp, 5, keys)

commit_setup = bidirectional_generate_commit_setup(pp, keys)


print(pp)
print(keys)
print(channel_token)
print(commit_setup)
print(ctypes.cast(pp, ctypes.c_char_p).value.decode('utf-8'))
print(ctypes.cast(keys, ctypes.c_char_p).value.decode('utf-8'))
print(ctypes.cast(channel_token, ctypes.c_char_p).value.decode('utf-8'))
print(ctypes.cast(commit_setup, ctypes.c_char_p).value.decode('utf-8'))
