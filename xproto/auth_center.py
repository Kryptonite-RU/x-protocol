from .x_utils import safe_encode
from .errors import UsrIDError, SrcIDError, InspIDError, CertificateError
from .consts import ID_LENGTH
from .crypto import PublicKey, KeyPair, pub_marshal

class AuthCenter:
    def __init__(self,
        users=None,
        services=None,
        inspectors_sig=None,
        inspectors_vko=None,
        scopes=None,
        auth_key=None,
        total_ids = 0):
        if users is None:
            users = {}
        if services is None:
            services = {}
        if inspectors_sig is None:
            inspectors_sig = {}
        if inspectors_vko is None:
            inspectors_vko = {}
        if scopes is None:
            scopes = {}
        if auth_key is None:
            auth_key = KeyPair()
        self.users = users
        self.services = services
        self.inspectors_sig = inspectors_sig
        self.inspectors_vko = inspectors_vko
        self.id_scope = scopes
        self.key = auth_key
        self.total_ids = total_ids

    def fresh_uid(self):
        self.total_ids += 1
        res = self.total_ids
        return res

    def fresh_srcid(self):
        self.total_ids += 1
        res = self.total_ids
        return res

    def fresh_iid(self):
        self.total_ids += 1
        res = self.total_ids
        return res

    def reg_user(self, user):
        ID = self.fresh_uid()
        user.ID = ID
        # some certification goes here 
        self.certify(user.key_pair.public)
        self.users[ID] = user.key_pair.public

    def reg_service(self, src):
        ID = self.fresh_srcid()
        src.ID = ID
        # some certification goes here 
        self.certify(src.key_pair.public)
        self.services[ID] = src.key_pair.public

    def reg_inspector(self, insp):
        assert(insp.scope != None)
        encoded = safe_encode(insp.scope)
        ID = self.fresh_iid()
        insp.ID = ID
        # some certification goes here 
        self.certify(insp.sign_pair.public)
        self.certify(insp.vko_pair.public)
        self.inspectors_sig[ID] = insp.sign_pair.public
        self.inspectors_vko[ID] = insp.vko_pair.public
        self.id_scope[ID] = encoded

    def scope2inspector(self, scope):
        encoded = safe_encode(scope)
        ID = find_id(self.id_scope, encoded)
        return ID

    def get_user(self, ID):
        if ID in self.users:
            pubkey =  self.users[ID]
            if self.verify_certificate(pubkey):
                return pubkey
            else:
                # certificate is invalid
                raise CertificateError
        else:
            raise UsrIDError

    def get_service(self, ID):
        if ID in self.services:
            pubkey = self.services[ID]
            if self.verify_certificate(pubkey):
                return pubkey
            else:
                # certificate is invalid
                raise CertificateError
        else:
            raise SrcIDError

    def get_inspector_vko(self, ID):
        if ID in self.inspectors_vko:
            pubkey = self.inspectors_vko[ID]
            if self.verify_certificate(pubkey):
                return pubkey
            else:
                # certificate is invalid
                raise CertificateError
        else:
            raise InspIDError

    def get_inspector_sig(self, ID):
        if ID in self.inspectors_sig:
            pubkey = self.inspectors_sig[ID]
            if self.verify_certificate(pubkey):
                return pubkey
            else:
                # certificate is invalid
                raise CertificateError
        else:
            raise InspIDError

    def verify_certificate(self, pubkey):
        cert = pubkey.certificate
        raw = pub_marshal(pubkey.key)
        return self.key.public.verify(raw, cert)

    def certify(self, pubkey):
        raw = pub_marshal(pubkey.key)
        cert = self.key.sign(raw)
        pubkey.certificate = cert


    def to_dict(self):
        d = {}
        d["users"] = {}
        d["services"] = {}
        d["inspectors"] = {}
        d["scopes"] = {}
        d["total_ids"] = self.total_ids
        d["key"] = self.key.to_dict()
        # write all users database
        users = self.users
        for (i, id) in enumerate(users.keys()):
            d["users"][i] = {}
            d["users"][i]["id"] = id
            d["users"][i]["key"] = users[id].to_dict()
        # write all services database
        services = self.services
        for (i, id) in enumerate(services.keys()):
            d["services"][i] = {}
            d["services"][i]["id"] = id
            d["services"][i]["key"] = services[id].to_dict()
        # write all inspectors database
        inspectors = self.inspectors_sig
        for (i, ID) in enumerate(inspectors.keys()):
            d["inspectors"][i] = {}
            d["inspectors"][i]["id"] = ID
            d["inspectors"][i]["sign_key"] = inspectors[ID].to_dict()
            d["inspectors"][i]["vko_key"] = self.inspectors_vko[ID].to_dict()
            d["inspectors"][i]["scope"] = self.id_scope[ID]
        return d

    @classmethod
    def from_dict(cls, d):
        users = {}
        services = {}
        inspectors_sig = {}
        inspectors_vko = {}
        scopes = {}
        total_ids = d["total_ids"]
        auth_key = KeyPair.from_dict(d["key"])
        d_usr = d["users"]
        for i in d_usr.keys():
            key = PublicKey.from_dict(d_usr[i]["key"])
            users[d_usr[i]["id"]] = key
        d_src = d["services"]
        for i in d_src.keys():
            key = PublicKey.from_dict(d_src[i]["key"])
            services[d_src[i]["id"]] = key
        d_insp = d["inspectors"]
        for i in d_insp.keys():
            ID = d_insp[i]["id"]
            sign_key = PublicKey.from_dict(d_insp[i]["sign_key"])
            vko_key = PublicKey.from_dict(d_insp[i]["vko_key"])
            scope = d_insp[i]["scope"]
            inspectors_sig[ID] = sign_key
            inspectors_vko[ID] = vko_key
            scopes[ID] = scope
        return cls(users=users, services=services,
            inspectors_vko=inspectors_vko,
            inspectors_sig=inspectors_sig,
            scopes=scopes, total_ids=total_ids,
            auth_key = auth_key)


AUTH = AuthCenter()

def find_id(d, scope):
    for k in d.keys():
        if d[k] == scope:
            return k
    raise InspIDError
