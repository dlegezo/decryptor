__all__ = ["parseConfig", "printConfig"]


from itertools import takewhile, compress, cycle


handlers = {
    "bytes": lambda raw, len, configParsed=None: raw[:len],
    "number": lambda raw, len, configParsed=None: int.from_bytes(raw[:len], "little"),
    "dynamic": lambda raw, len, configParsed: raw[
        : int.from_bytes(configParsed[len], "little")
    ],
    "ascii": lambda raw, len=None, configParsed=None: str(
        bytes(takewhile(lambda a: a > 0, raw)), encoding="UTF8"
    ),
    "wide": lambda raw, len=None, configParsed=None: str(
        bytes(takewhile(lambda a: a > 0, compress(raw, cycle([1, 0])))),
        encoding="UTF8",
    ),
}


def parseConfig(
    malwareFile: str,
    configDescription: list,
    configMagic: bytes = None,
    configOffset: int = 0,
) -> bytes:
    configParsed = {}

    with open(malwareFile, "rb") as f:
        malwareContent = f.read()
    if configMagic:
        configOffset = malwareContent.find(configMagic)
    for name, start, len, type in configDescription:
        raw = malwareContent[configOffset + start :]
        configParsed[name] = handlers[type](raw, len, configParsed)
    return configParsed


def printConfig(configParsed: dict) -> None:
    for k, v in configParsed.items():
        if type(v).__name__ == "bytes":
            print(f"{k} = 0x{v.hex()}")
        else:
            print(f"{k} = {v}")
