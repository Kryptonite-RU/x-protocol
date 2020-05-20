import pickle
import xproto as x

def dict_to_file(dict, file):
    with open(file, "wb") as f:
        pickle.dump(dict, f)

def file_to_dict(file):
    with open(file, "rb") as f:
        return pickle.load(f)

# def auth_to_json(auth):
#     #     users = {},
#     #     services = {}
#     #     inspectors_sig = {}
#     #     inspectors_vko = {}
#     #     scopes = {},
#     #     total_ids = 0
#     d = {}
#     d["id"] = insp.ID
#     d["scope"] = insp.scope
#     d["sign_private"] = insp.sign_pair.private
#     d["sign_certificate"] = src.sign_pair.public.certificate
#     d["vko_private"] = insp.vko_pair.private
#     d["vko_certificate"] = insp.vko_pair.public.certificate
#     d["database"] = insp.database
#     return json.dumps(d)


def load_src(filename):
    d = file_to_dict(filename)
    src = x.Service.from_dict(d)
    return src

def load_usr(filename):
    d = file_to_dict(filename)
    usr = x.AgentUser.from_dict(d)
    return usr

def load_insp(filename):
    d = file_to_dict(filename)
    insp = x.Inspector.from_dict(d)
    return insp

def load_auth(filename):
    d = file_to_dict(filename)
    auth = x.AuthCenter.from_dict(d)
    return auth

def to_file(filename, entity):
    d = entity.to_dict()
    dict_to_file(d, filename)
