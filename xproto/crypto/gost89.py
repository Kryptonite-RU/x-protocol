from pygost import gost28147 as gost89
from utils import array2pair, pair2array

class Gost89:

	def __init__(self, key, sbox = gost89.DEFAULT_SBOX):
		self.key = key
		self.sbox = sbox
		self.blen = 8 # in bytes


	def encrypt(self, msg):
		if len(msg) == 2:
			return gost89.encrypt(self.sbox, self.key, msg)
		elif len(msg) == 8:
			pair = array2pair(msg)
			length = len(msg)
			res = self.encrypt(pair)
			return pair2array(res, length)

	def decrypt(self, msg):
		if len(msg) == 2:
			return gost89.decrypt(self.sbox, self.key, msg)
		elif len(msg) == 8:
			pair = array2pair(msg)
			length = len(msg)
			res = self.decrypt(pair)
			return pair2array(res, length)
