from .crypto import rand_bytes
import xproto.crypto as crypto
from .x_utils import safe_encode
from .consts import REQUEST_MAXLEN

class Request:
    def __init__(self, SrcID, UID, scope, ttl, 
        key_pair = None, sig = None):
        self.srcid = safe_encode(SrcID)
        self.uid = safe_encode(UID)
        self.scope = safe_encode(scope) 
        self.ttl = safe_encode(ttl)
        content = self.srcid + self.uid + self.scope + self.ttl
        if sig:
            self.sig = sig
        else:
            self.sig = key_pair.sign(content)

    def content(self):
        res = self.srcid + self.uid + self.scope + self.ttl
        return res

    def encode(self):
        res = self.content()
        res += self.sig
        return res 


class Blob:
    def __init__(self, pub_ephem, UID, reply, 
        key_pair = None, sig = None):
        self.pub = safe_encode(pub_ephem)
        self.uid = safe_encode(UID)
        self.reply = safe_encode(reply) 
        content = self.pub + self.uid + self.reply
        if sig:
            self.sig = sig
        else:
            self.sig = key_pair.sign(content)

    def content(self):
        return self.pub + self.uid + self.reply 

    def encode(self):
        return self.content() + self.sig


class ReplyContent:
    def __init__(self, req, secdata, salt = rand_bytes(32)):
        self.request = req
        self.secdata = safe_encode(secdata)
        self.salt = safe_encode(salt)

    def request_len(self):
        length = len(self.request.encode())
        raw_len = (length).to_bytes(REQUEST_MAXLEN, 'big')
        return raw_len

    def encode(self):
        res = self.request_len()
        res += safe_encode(self.request)
        res += self.secdata
        res += self.salt
        return res

    def encrypt(self, key, iv = rand_bytes(16)):
        data = self.encode()
        cipher = crypto.Grasshopper(key)
        cbc = crypto.CBC(cipher)
        cbc.set_iv(iv)
        reply = cbc.encrypt(data)
        reply = iv + reply
        return reply


class Response:
    def __init__(self, ID, blob, ttl, answer, 
        key_pair = None, sig = None):
        self.iid = safe_encode(ID)
        self.blob = safe_encode(blob)
        self.ttl = safe_encode(ttl)
        self.answer = safe_encode(answer)
        content = self.iid + self.blob + self.ttl + self.answer
        if sig:
            self.sig = sig
        else:
            self.sig = key_pair.sign(content)

    def content(self):
        return self.iid + self.blob + self.ttl + self.answer

    def encode(self):
        return self.content() + self.sig