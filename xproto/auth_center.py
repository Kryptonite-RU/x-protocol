from .x_utils import safe_encode
from .consts import ID_LENGTH
from .crypto import PublicKey

class AuthCenter:
    def __init__(self,
        users = {},
        services = {},
        inspectors_sig = {},
        inspectors_vko = {},
        scopes = {},
        total_ids = 0):
        self.users = users
        self.services = services
        self.inspectors_sig = inspectors_sig
        self.inspectors_vko = inspectors_vko
        self.id_scope = scopes
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
        self.users[ID] = user.key_pair.public
        # some certification goes here 

    def reg_service(self, src):
        ID = self.fresh_srcid()
        src.ID = ID
        self.services[ID] = src.key_pair.public
        # some certification goes here 

    def reg_inspector(self, insp):
        assert(insp.scope != None)
        encoded = safe_encode(insp.scope)
        ID = self.fresh_iid()
        insp.ID = ID
        self.inspectors_sig[ID] = insp.sign_pair.public
        self.inspectors_vko[ID] = insp.vko_pair.public
        self.id_scope[ID] = encoded

    def scope2inspector(self, scope):
        encoded = safe_encode(scope)
        ID = find_id(self.id_scope, encoded)
        return ID

    def get_user(self, ID):
        try:
            return self.users[ID]
        except KeyError:
            return None

    def get_service(self, ID):
        try:
            return self.services[ID]
        except KeyError:
            return None

    def get_inspector_vko(self, ID):
        try:
            return self.inspectors_vko[ID]
        except KeyError:
            return None

    def get_inspector_sig(self, ID):
        try:
            return self.inspectors_sig[ID]
        except KeyError:
            return None

    def to_dict(self):
        d = {}
        d["users"] = {}
        d["services"] = {}
        d["inspectors"] = {}
        d["scopes"] = {}
        d["total_ids"] = self.total_ids
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
            scopes=scopes, total_ids=total_ids)


AUTH = AuthCenter()

def find_id(d, scope):
    for k in d.keys():
        if d[k] == scope:
            return k
    raise Exception