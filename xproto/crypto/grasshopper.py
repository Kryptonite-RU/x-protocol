from pygost import gost3412

class Grasshopper:
	def __init__(self, key):
		self.key = key
		self.blockcipher = gost3412.GOST3412Kuznechik(key)
		self.blen = 16 # in bytes

	def encrypt(self, msg):
		return self.blockcipher.encrypt(msg)

	def decrypt(self, msg):
		return self.blockcipher.decrypt(msg)