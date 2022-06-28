from Crypto.Hash import MD5

__all__ = ["checkHashGeneric"]


def checkHashGeneric(hasher: str, data: bytes, rightHash: bytes) -> None:
    match hasher:
        case "MD5":
            checkMD5_(data, rightHash)
        case _:
            print("Hashing algorithm isn't implemented yes")


def checkMD5_(data: bytes, rightMD5: bytes) -> bytes:
    md5 = MD5.new(data=data)
    return md5.digest() == rightMD5
