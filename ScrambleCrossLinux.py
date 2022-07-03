from argparse import ArgumentParser

from more_itertools import pairwise
from config import (
    configScrambleCrossDecryptedDescription,
    configScrambleCrossHeaderDescription,
)
from hasher import checkHashGeneric
from decryptor import decryptGeneric
from parser import parseConfig, printConfig


def decryptScrambleCross(
    decryptedFile: str, keyChaCha20: bytes, configHeader: dict
) -> None:

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

        if decryptedFile:
            with open(decryptedFile, "wb") as f:
                f.write(dec)
            print("Decrypted config dropped to {0}\n".format(decryptedFile))


if __name__ == "__main__":
    parser = ArgumentParser(description="ScrambleCross Linux version config decryptor")
    parser.add_argument(
        "-if",
        "--input",
        help="The input file with ScrambleCross Linux trojan",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-of",
        "--output",
        help="The output file with decrypted config",
        type=str,
        required=True,
    )
    args = parser.parse_args()

    configMagic = b"\x63\x66\x67\x5F\x64\x61\x74\x61"  # "cfg_data"
    keyChaCha20 = b"\x6Ft\x37\x31\x55\x77\x53\x66\x4B\x72\x48\x30\x4E\x6B\x52\x68\x6A\x4F\x6D\x58\x71\x46\x47\x4D\x41\x57\x44\x70\x6C\x7A\x34\x73\x00"  # o71UwSfKrH0NkRhjOmXqFGMAWDplz4s with trailing zero

    configHeader = parseConfig(
        malwareFile=args.input,
        configDescription=configScrambleCrossHeaderDescription,
        configMagic=configMagic,
    )
    decryptScrambleCross(args.output, keyChaCha20, configHeader)
    printConfig(
        parseConfig(
            malwareFile=args.output,
            configDescription=configScrambleCrossDecryptedDescription,
        )
    )
