from pygost.gost3410_vko import kek_34102012256 as kek

def vko(keypair_A, pub_B, ukm = 1):
    prv = keypair_A.private
    pub = pub_B.key
    curve = keypair_A.curve
    return kek(curve, prv, pub, ukm = ukm)
