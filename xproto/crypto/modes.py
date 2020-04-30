from pygost import gost3413

class ECB:
    def __init__(self, blockcipher, pad = None, unpad = None):
        self.enc = blockcipher.encrypt
        self.dec = blockcipher.decrypt
        self.blen = blockcipher.blen
        if pad == None:
            self.padding = lambda x : gost3413.pad2(x, self.blen)
        else:
            self.padding = pad
        if unpad == None:
            self.unpadding = lambda x : gost3413.unpad2(x, self.blen)
        else:
            self.unpadding = unpad

    def encrypt(self, text):
        buffer = self.padding(text)
        res = gost3413.ecb_encrypt(self.enc, self.blen, buffer)
        return res

    def decrypt(self, ctxt):
        res_padded = gost3413.ecb_decrypt(self.dec, self.blen, ctxt)
        res = self.unpadding(res_padded)
        return res

    def iv_length(self):
        return 0



class CBC:
    def __init__(self, blockcipher, pad = None, unpad = None):
        self.enc = blockcipher.encrypt
        self.dec = blockcipher.decrypt
        self.blen = blockcipher.blen
        if pad == None:
            self.padding = lambda x : gost3413.pad2(x, self.blen)
        else:
            self.padding = pad
        if unpad == None:
            self.unpadding = lambda x : gost3413.unpad2(x, self.blen)
        else:
            self.unpadding = unpad
        self.iv = bytes(blockcipher.blen)

    def set_iv(self, new_iv):
        self.iv = new_iv

    def encrypt(self, text):
        buffer = self.padding(text)
        res = gost3413.cbc_encrypt(self.enc, self.blen, buffer, self.iv)
        return res

    def decrypt(self, ctxt):
        res_padded = gost3413.cbc_decrypt(self.dec, self.blen, ctxt, self.iv)
        res = self.unpadding(res_padded)
        return res

    def iv_length(self):
        return len(self.iv)



class CTR:
    def __init__(self, blockcipher):
        self.enc = blockcipher.encrypt
        self.blen = blockcipher.blen
        self.iv = bytes(blockcipher.blen // 2)

    def set_iv(self, new_iv):
        self.iv = new_iv

    def encrypt(self, text):
        res = gost3413.ctr(self.enc, self.blen, text, self.iv)
        return res

    def decrypt(self, ctxt):
        res = gost3413.ctr(self.enc, self.blen, ctxt, self.iv)
        return res

    def iv_length(self):
        return len(self.iv)


class OFB:
    def __init__(self, blockcipher):
        self.enc = blockcipher.encrypt
        self.blen = blockcipher.blen
        self.iv = bytes(2 * blockcipher.blen)

    def set_iv(self, new_iv):
        self.iv = new_iv

    def encrypt(self, text):
        res = gost3413.ofb(self.enc, self.blen, text, self.iv)
        return res

    def decrypt(self, ctxt):
        res = gost3413.ofb(self.enc, self.blen, ctxt, self.iv)
        return res

    def iv_length(self):
        return len(self.iv)


class CFB:
    def __init__(self, blockcipher, pad = None, unpad = None):
        self.enc = blockcipher.encrypt
        self.dec = blockcipher.decrypt
        self.blen = blockcipher.blen
        if pad == None:
            self.padding = lambda x : gost3413.pad2(x, self.blen)
        else:
            self.padding = pad
        if unpad == None:
            self.unpadding = lambda x : gost3413.unpad2(x, self.blen)
        else:
            self.unpadding = unpad
        self.iv = bytes(2 * blockcipher.blen)

    def set_iv(self, new_iv):
        self.iv = new_iv

    def encrypt(self, text):
        buffer = self.padding(text)
        res = gost3413.cfb_encrypt(self.enc, self.blen, buffer, self.iv)
        return res

    def decrypt(self, ctxt):
        res_padded = gost3413.cfb_decrypt(self.dec, self.blen, ctxt, self.iv)
        res = self.unpadding(res_padded)
        return res

    def iv_length(self):
        return len(self.iv)


class MAC:
    def __init__(self, blockcipher):
        self.enc = blockcipher.encrypt
        self.blen = blockcipher.blen

    def mac(self, text):
        res = gost3413.mac(self.enc, self.blen, text)
        return res

    def verity(self, text, auth_code):
        return (self.mac(text) == auth_code)