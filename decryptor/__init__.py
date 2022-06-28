from Crypto.Cipher import ChaCha20


__all__ = ["configGeneric"]


def decryptGeneric(
    decryptor: str,
    enc: bytes,
    key: bytes,
    nonce: bytes = None,
    rounds: int = None,
) -> None:
    match decryptor:
        case "ChaCha20":
            return decryptChaCha20_(enc, key, nonce, rounds)
        case _:
            print("Decrypting algorithm isn't implemented yet")


def decryptChaCha20_(
    enc: bytes, key: bytes, nonce: bytes = None, rounds: int = None
) -> bytes:
    """The trickiest thing here in decryptor was the counter=11, in Python version one has to seek(64*counter)
    to get the same C effect. In ChaCha20 rounds is used as counter"""
    counter = rounds
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(64 * counter)  # counter setup only this way in stdlib
    return cipher.decrypt(enc)
