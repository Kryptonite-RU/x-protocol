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

def split_iv(data, mode = None):
    ivlen = mode.iv_length()
    iv = data[ : ivlen]
    data = data[ivlen : ]
    return (iv, data)


