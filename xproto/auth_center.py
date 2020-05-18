from .x_utils import safe_encode
from .consts import ID_LENGTH

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
        self.scopes = scopes
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
        encoded = safe_encode(insp.scope)
        ID = self.fresh_iid()
        insp.ID = ID
        self.inspectors_sig[ID] = insp.sign_pair.public
        self.inspectors_vko[ID] = insp.vko_pair.public
        self.scopes[encoded] = ID

    def scope2inspector(self, scope):
        encoded = safe_encode(scope)
        return self.scopes[encoded]

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

AUTH = AuthCenter()