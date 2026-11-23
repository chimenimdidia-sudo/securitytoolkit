import hashlib

def hash_text(text):
    data = text.encode("utf-8")
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }

def hash_file(file_obj):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    while True:
        chunk = file_obj.read(8192)
        if not chunk:
            break
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        sha512.update(chunk)
    return {
        "MD5": md5.hexdigest(),
        "SHA-1": sha1.hexdigest(),
        "SHA-256": sha256.hexdigest(),
        "SHA-512": sha512.hexdigest(),
    }

if __name__ == "__main__":
    print(hash_text("hello"))