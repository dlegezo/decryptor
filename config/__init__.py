__all__ = [
    "configScrambleCrossDecryptedDescription",
    "configScrambleCrossDecryptedDescription",
]

# each tuple in config's description has format (field name, start byte, length, format)
# possible formats are 'bytes', 'number', "ascii", "wide" and 'dynamic'
# the length of the last one is unknown at compile time
# length for 'dynamic' is not num, but another already inited field name in the same dict
# lengh of 'ascii' and 'wide' calculated at runtime to b'0' and b'00' correspondingly
configScrambleCrossHeaderDescription = [
    ("configMagic", 0, 8, "bytes"),
    ("configMD5", 8, 16, "bytes"),
    ("configChaCha20Nonce", 24, 12, "bytes"),
    ("configEncryptedLen", 36, 4, "bytes"),
    ("configEncrypted", 40, "configEncryptedLen", "dynamic"),
]

configScrambleCrossDecryptedDescription = [
    ("clientID", 0, 16, "bytes"),
    ("C2", 90, 0, "wide"),
    ("minLongPollSleep", 187, 2, "number"),
    ("maxLongPollSleep", 189, 2, "number"),
    ("minNetworkReverse", 191, 2, "number"),
    ("maxNetworkReverse", 193, 2, "number"),
]

# each tuple in process's description has format (process name, algorithm name)
processScrambleCrossDescription = [("hash", "MD5"), ("decrypt", "ChaCha20")]
