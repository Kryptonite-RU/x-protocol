from .crypto import rand_bytes
import xproto.crypto as crypto
from .x_utils import safe_encode, encode_id
from .consts import REQUEST_MAXLEN

class Request:
    def __init__(self, SrcID, UID, scope, ttl, 
        key_pair = None, sig = None):
        self.srcid = SrcID
        self.uid = UID
        self.scope = scope
        self.ttl = ttl
        if sig:
            self.sig = sig
        else:
            content  = encode_id(self.srcid)
            content += encode_id(self.uid)
            content += safe_encode(self.scope)
            content += safe_encode(self.ttl)
            self.sig = key_pair.sign(content)

    def content(self):
        res  = encode_id(self.srcid)
        res += encode_id(self.uid)
        res += safe_encode(self.scope)
        res += safe_encode(self.ttl)
        return res

    def encode(self):
        res = self.content()
        res += self.sig
        return res 


class Blob:
    def __init__(self, pub_ephem, UID, reply, 
        key_pair = None, sig = None):
        self.pub = safe_encode(pub_ephem)
        self.uid = UID
        self.reply = reply
        if sig:
            self.sig = sig
        else:
            content  = safe_encode(self.pub)
            content += encode_id(self.uid)
            content += safe_encode(self.reply)
            self.sig = key_pair.sign(content)

    def content(self):
        res  = safe_encode(self.pub)
        res += encode_id(self.uid)
        res += safe_encode(self.reply)
        return res

    def encode(self):
        return self.content() + self.sig


class ReplyContent:
    def __init__(self, req, secdata, salt = rand_bytes(32)):
        self.request = req
        self.secdata = secdata
        self.salt = salt

    def request_len(self):
        length = len(safe_encode(self.request))
        raw_len = (length).to_bytes(REQUEST_MAXLEN, 'big')
        return raw_len

    def encode(self):
        res = self.request_len()
        res += safe_encode(self.request)
        res += safe_encode(self.secdata)
        res += safe_encode(self.salt)
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
        self.iid = ID
        self.blob = blob
        self.ttl = ttl
        self.answer = answer
        if sig:
            self.sig = sig
        else:
            content  = encode_id(self.iid)
            content += safe_encode(self.blob)
            content += safe_encode(self.ttl)
            content += safe_encode(self.answer)
            self.sig = key_pair.sign(content)

    def content(self):
        res  = encode_id(self.iid)
        res += safe_encode(self.blob)
        res += safe_encode(self.ttl)
        res += safe_encode(self.answer)
        return res

    def encode(self):
        return self.content() + self.sig


class TTL:
    def __init__(self, from_date, expire_date):
        self.produced = from_date
        self.expired = expire_date

    def encode(self):
        res  = safe_encode(self.produced)
        res += safe_encode(self.expired)
        return res