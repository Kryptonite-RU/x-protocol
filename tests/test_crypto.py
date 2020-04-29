"""Unit tests for crypto module."""

import unittest
from xproto import crypto

class GrasshopperTest(unittest.TestCase):

    def test_grasshopper(self):
        key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        txt = crypto.hexdec("1122334455667700ffeeddccbbaa9988")
        ctxt = crypto.hexdec("7f679d90bebc24305a468d42b9d4edcd")
        cipher = crypto.Grasshopper(key)
        ctxt2 = cipher.encrypt(txt)
        txt2 = cipher.decrypt(ctxt2)
        self.assertEqual(ctxt, ctxt2)
        self.assertEqual(txt, txt2)

class MagmaTest(unittest.TestCase):

    def test_magma(self):
        key = crypto.hexdec("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        txt = crypto.hexdec("fedcba9876543210")
        ctxt = crypto.hexdec("4ee901e5c2d8ca3d")
        cipher = crypto.Magma(key)
        ctxt2 = cipher.encrypt(txt)
        ctxt2 = cipher.encrypt(txt)
        txt2 = cipher.decrypt(ctxt2)
        self.assertEqual(ctxt, ctxt2)
        self.assertEqual(txt, txt2)


class VKOTest(unittest.TestCase):

    def test_vko(self):
        # here we should check with the standard examples
        pass

    def test_same_keys(self):
        keys1 = crypto.KeyPair()
        keys2 = crypto.KeyPair()
        k1 = crypto.vko(keys1, keys2.public)
        k2 = crypto.vko(keys2, keys1.public)
        self.assertEqual(k1, k2)


class SignatureTest(unittest.TestCase):

    def test_signature(self):
        # here we should check with the standard examples
        pass 

    def test_sign_verity(self):
        msg = "Hello, world!"
        keys = crypto.KeyPair()
        pub = keys.public
        encoded = msg.encode()
        s = keys.sign(encoded)
        v = pub.verify(encoded, s)
        self.assertTrue(v)


class ModesTest(unittest.TestCase):

    # here we are trying to encrypt a message msg
    # using CTR with Grasshopper, and then CBC with Magma!
    def test_CTR_plus_CBC(self):
        msg = "Hello, world!"
        key1 = crypto.rand_bytes(32)
        key2 = crypto.rand_bytes(32)
        magma = crypto.Magma(key1) # with standard SBOX
        grass = crypto.Grasshopper(key2)
        # create encryption modes
        ctr = crypto.CTR(grass)
        cbc = crypto.CBC(magma) # standard padding type 2
        # IV's for encryption modes
        iv1 = crypto.rand_bytes(ctr.blen // 2) 
        iv2 = crypto.rand_bytes(cbc.blen)
        # set new IV's instead of zeros
        ctr.set_iv(iv1)
        cbc.set_iv(iv2)
        encoded = msg.encode()
        # NB : ctxt1 is of length 13 bytes
        # padding for CBC is needed
        # it is done internally (pad2)
        ctxt1 = ctr.encrypt(encoded)
        ctxt2 = cbc.encrypt(ctxt1)
        # here we decrypt and unpad internally
        new_ctxt1 = cbc.decrypt(ctxt2)
        new_txt = ctr.decrypt(new_ctxt1)
        self.assertEqual(new_txt.decode(), msg)

# TO DO:
# add test for modes
# add test for signature
# add test for VKO

if __name__ == "__main__":
    unittest.main()