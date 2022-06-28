__all__ = ["parseConfig", "printConfig"]


def parseConfig(ctx: (str, bytes, list)) -> bytes:
    malwareFile, configMagic, configDescription = ctx
    configParsed = {}
    configOffset = 0

    with open(malwareFile, "rb") as f:
        if configMagic:
            malwareContent = f.read()
            configOffset = f.seek(malwareContent.find(configMagic))

        for name, start, len, type in configDescription:
            f.seek(configOffset + start)
            match type:
                case "bytes":
                    configParsed[name] = f.read(len)
                case "number":
                    configParsed[name] = int.from_bytes(f.read(len), "little")
                case "dynamic":
                    configParsed[name] = f.read(
                        int.from_bytes(configParsed[len], "little")
                    )
                case "ascii":
                    asciiLen = 0
                    while f.read(1) != b"\x00":
                        asciiLen += 1
                    f.seek(configOffset + start)
                    configParsed[name] = str(f.read(asciiLen), encoding="UTF8")
                case "wide":
                    wideLen = 0
                    while f.read(2) != b"\x00\x00":
                        wideLen += 2
                    f.seek(configOffset + start)
                    configParsed[name] = str(f.read(wideLen), encoding="UTF16")
                case _:
                    print(
                        "Possible types in header config are bytes, number and dynamic"
                    )
    return configParsed


def printConfig(configParsed: dict) -> None:
    for k, v in configParsed.items():
        if type(v).__name__ == "bytes":
            print(f"{k} = 0x{v.hex()}")
        else:
            print(f"{k} = {v}")
