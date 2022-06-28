from argparse import ArgumentParser
from config import (
    configScrambleCrossDecryptedDescription,
    configScrambleCrossHeaderDescription,
)
from hasher import checkHashGeneric
from decryptor import decryptGeneric
from parser import parseConfig, printConfig


def decryptScrambleCross(ctx: (str, bytes, dict)) -> None:
    decryptedFile, keyChaCha20, configHeader = ctx

    if checkHashGeneric(
        "MD5",
        configHeader["configChaCha20Nonce"]
        + configHeader["configEncryptedLen"]
        + configHeader["configEncrypted"],
        configHeader["configMD5"],
    ):
        dec = decryptGeneric(
            "ChaCha20",
            configHeader["configEncrypted"],
            keyChaCha20,
            configHeader["configChaCha20Nonce"],
            11,
        )

        with open(decryptedFile, "wb") as f:
            f.write(dec)
        print("Decrypted config dropped to {0}\n".format(decryptedFile))


if __name__ == "__main__":
    parser = ArgumentParser(description="ScrambleCross Linux version config decryptor")
    parser.add_argument("-if", help="The input file with ScrambleCross Linux trojan")
    parser.add_argument("-of", help="The output file with decrypted config")
    args = vars(parser.parse_args())

    configMagic = b"\x63\x66\x67\x5F\x64\x61\x74\x61"  # "cfg_data"
    keyChaCha20 = b"\x6F\x37\x31\x55\x77\x53\x66\x4B\x72\x48\x30\x4E\x6B\x52\x68\x6A\x4F\x6D\x58\x71\x46\x47\x4D\x41\x57\x44\x70\x6C\x7A\x34\x73\x00"  # o71UwSfKrH0NkRhjOmXqFGMAWDplz4s with trailing zero

    ctx = (args["if"], configMagic, configScrambleCrossHeaderDescription)
    configHeader = parseConfig(ctx)
    ctx = (args["of"], keyChaCha20, configHeader)
    decryptScrambleCross(ctx)
    ctx = (args["of"], None, configScrambleCrossDecryptedDescription)
    printConfig(parseConfig(ctx))
