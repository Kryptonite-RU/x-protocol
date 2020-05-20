from pygost import gost3410
from pygost import gost34112012
from .utils import rand_bytes

class PublicKey:
    def __init__(
        self,
        curve_type=None, 
        pub_key=None, 
        priv_key=None,
        cert=None):
        curve = gost3410.CURVES[curve_type]
        if pub_key == None:
            self.key = gost3410.public_key(curve, priv_key)
        else:
            if type(pub_key) == tuple:
                self.key = pub_key
            else: # type = bytes/bytearray
                self.key = gost3410.pub_unmarshal(pub_key)
        self.curve = curve
        self.curve_type = curve_type
        self.certificate = cert

    def verify(self, msg, s):
        digest = gost34112012.GOST34112012(msg).digest()
        return gost3410.verify(self.curve, self.key, digest, s)

    def encode(self):
        return gost3410.pub_marshal(self.key)

    def __eq__(self, other):
        ch1 = (self.key == other.key)
        ch2 = (self.curve == other.curve)
        return (ch1 and ch2)

    def to_dict(self):
        d = {}
        d["key"] = self.key
        d["certificate"] = self.certificate
        d["curve_type"] = self.curve_type
        return d

    @classmethod
    def from_dict(cls, d):
        key = d["key"]
        cert = d["certificate"]
        curve_type = d["curve_type"]
        return cls(curve_type=curve_type, 
            pub_key=key, cert=cert)





class KeyPair:
    def __init__(
        self, 
        raw_key=rand_bytes(32),
        curve_type="id-tc26-gost-3410-2012-256-paramSetA",
        private=None,
        cert=None):
        self.curve = gost3410.CURVES[curve_type]
        self.curve_type = curve_type
        if private == None:
            self.private = gost3410.prv_unmarshal(raw_key)
        else:
            self.private = private
        self.public = PublicKey(curve_type=self.curve_type, 
            priv_key=self.private, cert=cert)

    def sign(self, msg):
        digest = gost34112012.GOST34112012(msg).digest()
        s = gost3410.sign(self.curve, self.private, digest)
        return s

    def __eq__(self, other):
        ch1 = (self.public == other.public)
        ch2 = (self.private == other.private)
        ch3 = (self.curve_type == other.curve_type)
        return (ch1 and ch2 and ch3)

    def to_dict(self):
        d = {}
        d["curve_type"] = self.curve_type 
        d["private"] = self.private
        d["cert"] = self.public.certificate
        return d

    @classmethod
    def from_dict(cls, d):
        curve_type = d["curve_type"]
        priv_key = d["private"]
        cert = d["cert"]
        return KeyPair(curve_type=curve_type, 
            private=priv_key, cert=cert)




def export_public_key(
    key, 
    curve_type = "id-tc26-gost-3410-2012-256-paramSetA"):
    curve = gost3410.CURVES[curve_type]
    if isinstance(key, tuple):
        return PublicKey(curve_type=curve_type, pub_key=key)
    else:
        key = gost3410.pub_unmarshal(key)
        return PublicKey(curve_type=curve_type, pub_key=key)
