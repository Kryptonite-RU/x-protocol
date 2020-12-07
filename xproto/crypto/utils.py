import os

def array2pair(arr):
    left = 0
    right = 0
    if len(arr) == 8:
        for i in range(4):
            left *= 16
            left += arr[i]
        for i in range(4, 8):
            right *= 16
            right += arr[i]
    return (left, right)

# should return n GOOD random bytes
def rand_bytes(n):
    return os.urandom(n)
