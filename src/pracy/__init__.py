def main():
    import argparse
    from pathlib import Path

    from .analysis.scheme import analyze_scheme
    from .backend.compiler.all import compile
    from .backend.export.charm import Charm
    from .backend.export.relic import Relic
    from .frontend.parsing import parse_json

    parser = argparse.ArgumentParser(
        prog=__name__,
        description="Generates a runnable implementation of "
        "an ABE scheme based on a JSON specification",
    )
    parser.add_argument(
        "-b",
        "--backend",
        help="specify the syntax of the generated code (default=relic)",
        choices=("relic", "charm"),
        default="relic",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        help=(
            "the directory where to place the generated code (if not"
            "provided, code is written to stdout instead)"
        ),
    )
    parser.add_argument(
        "scheme",
        metavar="scheme.json",
        help="path to the JSON specification of the scheme",
    )

    args = parser.parse_args()

    with open(args.scheme, encoding="utf-8") as f:
        json_input = f.read()

    raw_scheme = parse_json(json_input)
    scheme = analyze_scheme(raw_scheme)
    setup, keygen, encrypt, decrypt = compile(scheme)

    backend = Relic() if args.backend == "relic" else Charm()

    if args.outdir:
        out_dir = Path(args.outdir)
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(out_dir / "setup.gen", "w", encoding="utf-8") as f:
            f.write(backend.export(setup))

        with open(out_dir / "keygen.gen", "w", encoding="utf-8") as f:
            f.write(backend.export(keygen))

        with open(out_dir / "encrypt.gen", "w", encoding="utf-8") as f:
            f.write(backend.export(encrypt))

        with open(out_dir / "decrypt.gen", "w", encoding="utf-8") as f:
            f.write(backend.export(decrypt))

    else:
        print(backend.export(setup))

        print(backend.export(keygen))

        print(backend.export(encrypt))

        print(backend.export(decrypt))


if __name__ == "__main__":
    main()
