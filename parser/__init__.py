__all__ = ["parseConfig", "printConfig"]


def handlerAscii(raw, len=None, configParsed=None):
    cached = b""
    offset = 0
    while raw[offset] != b"\x00":
        cached += raw[offset]
        offset += 1
    return str(cached, encoding="UTF8")


def handlerWide(raw, len=None, configParsed=None):
    cached = b""
    offset = 0
    while (aux := raw[offset : offset + 2]) != b"\x00\x00":
        cached += aux
        offset += 2
    return str(cached, encoding="UTF16")


handlers = {
    "bytes": lambda raw, len, configParsed=None: raw[:len],
    "number": lambda raw, len, configParsed=None: int.from_bytes(raw[:len], "little"),
    "dynamic": lambda raw, len, configParsed: raw[
        : int.from_bytes(configParsed[len], "little")
    ],
    "ascii": handlerAscii,
    "wide": handlerWide,
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
            configOffset = f.seek(malwareContent.find(configMagic))

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
