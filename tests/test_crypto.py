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

    # def __init__(self):
    #     self.key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    #     self.txt =  crypto.hexdec("1122334455667700ffeeddccbbaa9988")
    #     self.txt += crypto.hexdec("00112233445566778899aabbcceeff0a")
    #     self.txt += crypto.hexdec("112233445566778899aabbcceeff0a00")
    #     self.txt += crypto.hexdec("2233445566778899aabbcceeff0a0011")
    #     self.grass = crypto.Grasshopper(key)


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

    def test_ECB(self):
        key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        txt =  crypto.hexdec("1122334455667700ffeeddccbbaa9988")
        txt += crypto.hexdec("00112233445566778899aabbcceeff0a")
        txt += crypto.hexdec("112233445566778899aabbcceeff0a00")
        txt += crypto.hexdec("2233445566778899aabbcceeff0a0011")
        cip = crypto.Grasshopper(key)
        mode = crypto.ECB(cip,
            pad   = lambda x : crypto.pad1(x, cip.blen),
            unpad = lambda x : crypto.pad1(x, cip.blen))
        ctxt = mode.encrypt(txt)
        res  = crypto.hexdec("7f679d90bebc24305a468d42b9d4edcd")
        res += crypto.hexdec("b429912c6e0032f9285452d76718d08b")
        res += crypto.hexdec("f0ca33549d247ceef3f5a5313bd4b157")
        res += crypto.hexdec("d0b09ccde830b9eb3a02c4c5aa8ada98")
        self.assertEqual(ctxt, res)

    def test_CBC(self):
        key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        txt =  crypto.hexdec("1122334455667700ffeeddccbbaa9988")
        txt += crypto.hexdec("00112233445566778899aabbcceeff0a")
        txt += crypto.hexdec("112233445566778899aabbcceeff0a00")
        txt += crypto.hexdec("2233445566778899aabbcceeff0a0011")
        cip = crypto.Grasshopper(key)
        IV  = crypto.hexdec('1234567890abcef0a1b2c3d4e5f00112')
        IV += crypto.hexdec('23344556677889901213141516171819')
        mode = crypto.CBC(cip,
            pad   = lambda x : crypto.pad1(x, cip.blen),
            unpad = lambda x : crypto.pad1(x, cip.blen))
        mode.set_iv(IV)
        ctxt = mode.encrypt(txt)
        res  = crypto.hexdec('689972d4a085fa4d90e52e3d6d7dcc27')
        res += crypto.hexdec('2826e661b478eca6af1e8e448d5ea5ac')
        res += crypto.hexdec('fe7babf1e91999e85640e8b0f49d90d0')
        res += crypto.hexdec('167688065a895c631a2d9a1560b63970')
        self.assertEqual(ctxt, res)

    def test_CTR(self):
        key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        txt =  crypto.hexdec("1122334455667700ffeeddccbbaa9988")
        txt += crypto.hexdec("00112233445566778899aabbcceeff0a")
        txt += crypto.hexdec("112233445566778899aabbcceeff0a00")
        txt += crypto.hexdec("2233445566778899aabbcceeff0a0011")
        cip = crypto.Grasshopper(key)
        IV = crypto.hexdec('1234567890abcef0')
        mode = crypto.CTR(cip)
        mode.set_iv(IV)
        ctxt = mode.encrypt(txt)
        res  = crypto.hexdec('f195d8bec10ed1dbd57b5fa240bda1b8')
        res += crypto.hexdec('85eee733f6a13e5df33ce4b33c45dee4')
        res += crypto.hexdec('a5eae88be6356ed3d5e877f13564a3a5')
        res += crypto.hexdec('cb91fab1f20cbab6d1c6d15820bdba73')
        self.assertEqual(ctxt, res)

    def test_OFB(self):
        key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        txt =  crypto.hexdec("1122334455667700ffeeddccbbaa9988")
        txt += crypto.hexdec("00112233445566778899aabbcceeff0a")
        txt += crypto.hexdec("112233445566778899aabbcceeff0a00")
        txt += crypto.hexdec("2233445566778899aabbcceeff0a0011")
        cip = crypto.Grasshopper(key)
        IV  = crypto.hexdec('1234567890abcef0a1b2c3d4e5f00112')
        IV += crypto.hexdec('23344556677889901213141516171819')
        mode = crypto.OFB(cip)
        mode.set_iv(IV)
        ctxt = mode.encrypt(txt)
        res  = crypto.hexdec('81800a59b1842b24ff1f795e897abd95')
        res += crypto.hexdec('ed5b47a7048cfab48fb521369d9326bf')
        res += crypto.hexdec('66a257ac3ca0b8b1c80fe7fc10288a13')
        res += crypto.hexdec('203ebbc066138660a0292243f6903150')
        self.assertEqual(ctxt, res)

    def test_CFB(self):
        key = crypto.hexdec("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
        txt =  crypto.hexdec("1122334455667700ffeeddccbbaa9988")
        txt += crypto.hexdec("00112233445566778899aabbcceeff0a")
        txt += crypto.hexdec("112233445566778899aabbcceeff0a00")
        txt += crypto.hexdec("2233445566778899aabbcceeff0a0011")
        cip = crypto.Grasshopper(key)
        IV  = crypto.hexdec('1234567890abcef0a1b2c3d4e5f00112')
        IV += crypto.hexdec('23344556677889901213141516171819')
        mode = crypto.CFB(cip,
            pad   = lambda x : crypto.pad1(x, cip.blen),
            unpad = lambda x : crypto.pad1(x, cip.blen))
        mode.set_iv(IV)
        ctxt = mode.encrypt(txt)
        res  = crypto.hexdec('81800a59b1842b24ff1f795e897abd95')
        res += crypto.hexdec('ed5b47a7048cfab48fb521369d9326bf')
        res += crypto.hexdec('79f2a8eb5cc68d38842d264e97a238b5')
        res += crypto.hexdec('4ffebecd4e922de6c75bd9dd44fbf4d1')
        self.assertEqual(ctxt, res)



# TO DO:
# add test for signature
# add test for VKO

if __name__ == "__main__":
    unittest.main()