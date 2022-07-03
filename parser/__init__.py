__all__ = ["parseConfig", "printConfig"]


def handlerAscii(f, len=None, configParsed=None):
    cached = b""
    while (cached := f.read(1)) != b"\x00":
        cached += aux
    return str(cached, encoding="UTF8")


def handlerWide(f, len=None, configParsed=None):
    cached = b""
    while (aux := f.read(2)) != b"\x00\x00":
        cached += aux
    return str(cached, encoding="UTF16")


handlers = {
    "bytes": lambda f, len, configParsed=None: f.read(len),
    "number": lambda f, len, configParsed=None: int.from_bytes(f.read(len), "little"),
    "dynamic": lambda f, len, configParsed: f.read(
        int.from_bytes(configParsed[len], "little")
    ),
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
        if configMagic:
            malwareContent = f.read()
            configOffset = f.seek(malwareContent.find(configMagic))

        for name, start, len, type in configDescription:
            f.seek(configOffset + start)
            configParsed[name] = handlers[type](f, len, configParsed)
    return configParsed


def printConfig(configParsed: dict) -> None:
    for k, v in configParsed.items():
        if type(v).__name__ == "bytes":
            print(f"{k} = 0x{v.hex()}")
        else:
            print(f"{k} = {v}")
