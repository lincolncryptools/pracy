#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess as sp
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def run_pracy(scheme, relic_src_dir):
    """
    Run the pracy compiler for `scheme` and place the generated
    source code in `relic_src_dir`.

    Returns `False`, if any subcommand fails, `True`, otherwise.
    """
    logger.info(f"Compiling JSON scheme '{scheme}' to source code")
    cmd = ["python", "-m", "pracy", f"{scheme}", "-o", f"{relic_src_dir}"]
    logger.info(" ".join(cmd))
    res = sp.run(cmd, capture_output=True)

    if res.returncode != 0:
        logger.error(f"Compilation of scheme '{scheme}' failed:")
        logger.error(f"stdout: '{res.stdout}'")
        logger.error(f"stderr: '{res.stderr}'")
        return False
    logging.info("Compiling JSON scheme: Done")
    return True


def run_cmake(relic_build_dir, options):
    """
    Run CMake to configure the RELIC backend for the given `options`.
    CMake is executed from within `relic_build_dir`.

    The contents of `options` is used to provide compile-time parameters.

    Returns `False`, if any subcommand fails, `True`, otherwise.
    """
    POLICY_LEN = options["policy_len"]
    BENCH_ITERS = options["bench_iters"]
    MULTI_AUTH = options["multi_auth"]
    OT_NEGS = options["ot_negs"]
    cmd = [
        "cmake",
        f"-DPOLICY_LEN={POLICY_LEN}",
        f"-DBENCH_ITERS={BENCH_ITERS}",
        f"-DMULTI_AUTH={MULTI_AUTH}",
        f"-DOT_NEGS={OT_NEGS}",
        "-DCMAKE_BUILD_TYPE=Release",
        "..",
    ]
    logger.info(" ".join(cmd))
    res = sp.run(cmd, cwd=relic_build_dir, capture_output=True)
    if res.returncode != 0:
        logger.error("CMake failed for Relic backend:")
        logger.error(f"stdout: '{res.stdout}'")
        logger.error(f"stderr: '{res.stderr}'")
        return False
    logger.info("Running CMake: Done")
    return True


def run_make(relic_build_dir):
    """
    Build the RELIC backend using `make` in `relic_build_dir`.

    Returns `False`, if any subcommand fails, `True`, otherwise.
    """
    logger.info("Compiling Relic backend")
    cmd = ["make"]
    logger.info(" ".join(cmd))
    res = sp.run(cmd, cwd=relic_build_dir, capture_output=True)
    if res.returncode != 0:
        logger.error("Compilation of Relic backend failed")
        logger.error(f"stdout: '{res.stdout}'")
        logger.error(f"stderr: '{res.stderr}'")
        return False
    logger.info("Compiling backend: Done")
    return True


def run_backend(relic_build_dir):
    """
    Run the compiled executable `main` (located in `relic_build_dir`).

    Returns `False`, if any subcommand fails, `True`, otherwise.
    """
    logger.info("Running Relic backend")
    cmd = ["./main"]
    res = sp.run(cmd, cwd=relic_build_dir, capture_output=True)
    timings = res.stdout.decode("utf-8")
    header = "---------- OUTPUT BEGIN ----------"
    footer = "---------- OUTPUT END ------------"
    logger.info(f"\n{header}\n{timings}\n{footer}")
    if res.returncode != 0:
        logger.error("Relic backend failed")
        logger.error(f"stderr: '{res.stderr}'")
        return False
    logger.info("Running backend: Done")
    return True


def main():
    """
    Searches for all ABE scheme specs in the schemes folder and
    tests the entire compilation chain.

    This includes:
    1. generation source code from JSON
    2. running CMake for RELIC backend
    3. running Make for RELIC backend
    4. running the resulting executable
    """
    logging.basicConfig(
        stream=sys.stdout, level=logging.INFO, format="[%(levelname)s] %(message)s"
    )

    errors = 0

    project_path = Path(os.path.realpath(__file__)).parent.parent
    schemes_path = project_path / "schemes"

    parser = argparse.ArgumentParser(
        prog=__name__,
        description="Generate Charm code for all schemes in a folder",
    )

    parser.add_argument("-n", "--name", help="the scheme which should be tested")

    args = parser.parse_args()

    def matches_name_pattern(s):
        return args.name is None or s.startswith(args.name)

    relic_src_dir = project_path / "backends" / "relic" / "src"
    relic_build_dir = project_path / "backends" / "relic" / "_build"

    option_sets = [
        {
            "policy_len": 5,
            "bench_iters": 10,
            "multi_auth": "off",
            "ot_negs": "off",
        },
        {
            "policy_len": 5,
            "bench_iters": 10,
            "multi_auth": "on",
            "ot_negs": "off",
        },
        {
            "policy_len": 5,
            "bench_iters": 10,
            "multi_auth": "on",
            "ot_negs": "on",
        },
    ]

    schemes = schemes_path.glob("*.json")
    for scheme in sorted(schemes):
        if not matches_name_pattern(scheme.stem):
            continue

        options = [option_sets[0]]
        if scheme.stem.startswith("a") or scheme.stem.startswith("b"):
            options.append(option_sets[1])
        if scheme.stem.startswith("b"):
            options.append(option_sets[2])

        for opts in options:
            if not run_pracy(scheme, relic_src_dir):
                errors += 1
                continue

            if not run_cmake(relic_build_dir, opts):
                errors += 1
                continue

            if not run_make(relic_build_dir):
                errors += 1
                continue

            if not run_backend(relic_build_dir):
                errors += 1
                continue

    if errors > 0:
        logger.error(
            f"At least {errors} schemes were not generated/compiled/run properly"
        )
        sys.exit(3)


if __name__ == "__main__":
    main()
