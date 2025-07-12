import sys
import base64
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

def decryptRC(blob_b64: str, key_str: str) -> str:
   
    key = key_str.encode('utf-8')
    if len(key) != 24:
        raise ValueError(f"needs to be 24 bytes, current {len(key)}")

    raw = base64.b64decode(blob_b64)
    if len(raw) < 8:
        raise ValueError("too short for IV")

    iv = raw[:8]
    ct = raw[8:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    pt_padded = cipher.decrypt(ct)

    try:
        pt = unpad(pt_padded, DES3.block_size)
    except ValueError:
        pt = pt_padded.rstrip(b'\0')

    return pt.decode('utf-8', errors='ignore')

if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        sys.exit(1)

    blob = sys.argv[1]
    des_key = sys.argv[2] if len(sys.argv) == 3 else "rcmail-!24ByteDESkey*Str"

    try:
        clear = decryptRC(blob, des_key)
        print(clear)
    except Exception as e:
        print("error:", e)
        sys.exit(2)
