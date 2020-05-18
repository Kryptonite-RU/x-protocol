from .crypto import rand_bytes
import xproto.crypto as crypto
from .x_utils import safe_encode, encode_id, cut_signature, parse_number, parse_str
from .consts import *
import datetime


class TTL:
    def __init__(self, expire_date, produced=datetime.datetime.now().date()):
        self.produced = produced
        self.expired = expire_date

    def encode(self):
        res  = safe_encode(self.produced)
        res += safe_encode(self.expired)
        return res

    def to_dict(self):
        d = {}
        d["produced"] = self.produced
        d["expired"] = self.expired
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(d["expired"], produced = d["produced"])

    @classmethod
    def parse(cls, raw):
        rawstr1 = raw.decode()[ : DATE_LENGTH]
        rawstr2 = raw.decode()[DATE_LENGTH : ]
        res1 = datetime.datetime.strptime(rawstr1, '%Y-%m-%d')
        res2 = datetime.datetime.strptime(rawstr2, '%Y-%m-%d')
        ttl = cls(res2.date(), produced=res1.date())
        return ttl



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

    def to_dict(self):
        d = {}
        d["srcid"] = self.srcid
        d["uid"] = self.uid
        d["scope"] = self.scope
        d["ttl"] = self.ttl.to_dict()
        d["sig"] = self.sig

    @classmethod
    def from_dict(cls, d):
        srcid = d["srcid"]
        uid = d["uid"]
        scope = d["scope"]
        ttl = TTL.from_dict(d["ttl"])
        sig = d["sig"]
        return cls(srcid, uid, scope, ttl, sig=sig)

    @classmethod
    def parse(cls, raw):
        sig   = raw[-SIG_LENGTH : ]
        raw = cut_signature(raw)
        SrcID = parse_number(raw[: ID_LENGTH])
        UID   = parse_number(raw[ID_LENGTH : 2*ID_LENGTH])
        ttl   = TTL.parse(raw[-TTL_LENGTH : ])
        scope = parse_str(raw[2*ID_LENGTH : -TTL_LENGTH])
        req = cls(SrcID, UID, scope, ttl, sig=sig)
        return req



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

    def to_dict(self):
        d = {}
        d["pub"] = self.pub
        d["uid"] = self.uid
        d["reply"] = self.reply
        d["sig"] = self.sig

    @classmethod
    def from_dict(cls, d):
        pub = d["pub"]
        uid = d["uid"]
        reply = d["reply"]
        sig = d["sig"]
        return cls(pub, uid, reply, sig=sig)

    @classmethod
    def parse(cls, raw):
        pub_ephem = raw[: SIG_LENGTH]
        UID   = parse_number(raw[SIG_LENGTH : SIG_LENGTH + ID_LENGTH])
        reply = raw[SIG_LENGTH + ID_LENGTH : ]
        sig   = reply[-SIG_LENGTH : ]
        reply = cut_signature(reply)
        blob  = cls(pub_ephem, UID, reply, sig=sig)
        return blob



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

    @classmethod
    def parse(cls, raw):
        req_len = parse_number(raw[:REQUEST_MAXLEN])
        raw = raw[REQUEST_MAXLEN : ]
        req = Request.parse(raw[ : req_len])
        secdata = parse_str(raw[req_len : -SALT_LENGTH])
        salt = raw[ -SALT_LENGTH : ]
        return cls(req, secdata, salt=salt)



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

    def to_dict(self):
        d = {}
        d["iid"] = self.iid
        d["blob"] = self.blob.to_dict()
        d["ttl"] = self.ttl.to_dict()
        d["ans"] = self.answer
        d["sig"] = self.sig

    @classmethod
    def from_dict(cls, d):
        iid = d["iid"]
        blob = Blob.from_dict(d["blob"])
        ttl = TTL.from_dict(d["ttl"])
        ans = d["ans"]
        sig = d["sig"]
        return cls(iid, blob, ttl, ans, sig=sig)

    @classmethod
    def parse(cls):
        sig = raw[-SIG_LENGTH : ]
        raw = cut_signature(raw)
        ans = raw[-ANS_LENGTH : ]
        ttl = TTL.parse(raw[-(ANS_LENGTH + TTL_LENGTH) : -ANS_LENGTH])
        ID = parse_number(raw[: ID_LENGTH])
        raw = raw[ID_LENGTH : ]
        raw_blob = raw[ : -(ANS_LENGTH + TTL_LENGTH)]
        blob = Blob.parse(raw_blob)
        resp = cls(ID, blob, ttl, ans, sig=sig)
        return resp


