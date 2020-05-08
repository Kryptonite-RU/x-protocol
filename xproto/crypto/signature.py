from pygost import gost3410
from pygost import gost34112012
from .utils import rand_bytes

class PublicKey:
    def __init__(
        self, 
        curve, 
        pub_key = None, 
        priv_key = None):
        if pub_key == None:
            self.key = gost3410.public_key(curve, priv_key)
        else:
            if type(pub_key) == tuple:
                self.key = pub_key
            else: # type = bytes/bytearray
                self.key = gost3410.pub_unmarshal(pub_key)
        self.curve = curve
        self.certificate = None

    def verify(self, msg, s):
        digest = gost34112012.GOST34112012(msg).digest()
        return gost3410.verify(self.curve, self.key, digest, s)

    def encode(self):
        return gost3410.pub_marshal(self.key)




class KeyPair:
    def __init__(
        self, 
        raw_key = rand_bytes(32),
        curve_type = "id-tc26-gost-3410-2012-256-paramSetA"):
        self.curve = gost3410.CURVES[curve_type]
        self.private = gost3410.prv_unmarshal(raw_key)
        self.public = PublicKey(self.curve, priv_key = self.private)

    def sign(self, msg):
        digest = gost34112012.GOST34112012(msg).digest()
        s = gost3410.sign(self.curve, self.private, digest)
        return s


def export_public_key(
    key, 
    curve_type = "id-tc26-gost-3410-2012-256-paramSetA"):
    curve = gost3410.CURVES[curve_type]
    if isinstance(key, tuple):
        return PublicKey(curve, pub_key = key)
    else:
        # decode first, then create key
        # key = gost3410.pub_unmarshal(key)
        key = gost3410.pub_unmarshal(key)
        return PublicKey(curve, pub_key = key)
