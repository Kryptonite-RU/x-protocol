from .consts import ID_LENGTH

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