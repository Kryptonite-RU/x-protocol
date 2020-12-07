from .consts import ID_LENGTH, SIG_LENGTH
import base64

def safe_encode(x):
    try:
        res = x.encode()
    except AttributeError:
        if type(x) == bytes:
            res = x
        elif x is None:
            res = None
        else:
            res = safe_encode(str(x))
        # any other types?  
    return res

def encode_id(x):
    res = (x).to_bytes(ID_LENGTH, 'big')
    return res

def split_iv(data, mode = None):
    ivlen = mode.iv_length()
    iv = data[ : ivlen]
    data = data[ivlen : ]
    return (iv, data)

def find_date(dates, date):
    sort = sorted(dates)
    # the user registers AFTER the blob was requested
    if sort[0] > date:
        return None
    for i in range(len(dates) - 1):
        curr = sort[i]
        nxt = sort[i+1]
        if curr <= date < nxt:
            return curr
    return sort[-1]


def cut_signature(data):
    return data[: -SIG_LENGTH]

def parse_number(raw):
    return int.from_bytes(raw, 'big')

def parse_str(raw):
    return raw.decode()

def dict_utf(d):
    res = dict()
    for key, value in d.items():
        if type(value) is str:
            value_res = 'NOBASE64_' + value
        elif type(value) is bytes:
            value_res = str(b'BASE64_' + base64.b64encode(value), 'utf-8')
        elif type(value) is dict:
            value_res = dict_utf(value)
        else:
            value_res = value
        res[key] = value_res
    return res

def utf_dict(d):
    res = dict()
    for key, value in d.items():
        if type(value) is str:
            value = value.split('_')
            value_res = base64.b64decode(value[1]) if value[0] == 'BASE64' else value[1]
        elif type(value) is dict:
            value_res = utf_dict(value)
        elif type(value) is list:
            value_res = tuple(value)
        else:
            value_res = value
        res[key] = value_res
    return res

