"""
Please refer to the documentation provided
"""

from cProfile import Profile
from pstats import SortKey, Stats
import unittest
import json
import os
from CharmBackend import template, parsing


def run_scheme(meta_path, schemes_path, benchmark):
    """
    Args:
        meta_path (str): path to meta.json
        scheme_path (str): path scheme-folder containing e.g. setup.gen
                           to run all schemes: "path/to/schemes/"
                           to run specific scheme: "path/to/schemes/a_0"
        benchamrk (bool): true/false to benchmark

    Returns:
        None

    Example: run_scheme("schemes/meta.json", "schemes/", False)
        >>> None
    """
    meta = parsing.parse_json(meta_path)
    test_path = "CharmBackend/tests"
    if not os.path.exists(schemes_path):
        assert False, "no scheme files found, please check the specified path"
    for root, dirs, files in os.walk(schemes_path):
        if root == schemes_path and dirs:
            continue
        ir = root + "/"
        suite = load_tests(meta, ir, test_path)
        runner = unittest.TextTestRunner(verbosity=2)
        if benchmark:
            with Profile() as profile:
                runner.run(suite)
                (Stats(profile).strip_dirs().sort_stats(SortKey.CALLS).print_stats())
        else:
            runner.run(suite)


########## TESTING ##########
def load_tests(meta, scheme_path, test_path):
    """
    Args:
        meta
        scheme_path
        test_path

    Returns:
        test suite
    """
    types = [v["syntax"] for k, v in meta["types"].items()]
    for root, folders, files in os.walk(test_path):

        for file in files:
            setup_file = os.path.join(root, file)
            setup_data = parsing.parse_json(setup_file)

            if isinstance(setup_data, list):
                if "tau" in setup_file:  # tau mapping tests (tests/tau.json)
                    for idx, case in enumerate(setup_data):
                        test_method = create_tau_test_case(meta, case)
                        setattr(unittest.TestCase, f"test_TAU-{idx}", test_method)

            elif isinstance(setup_data, dict):
                if (
                    "correctness" in setup_file
                ):  # correctness tests (tests/correctness.json)
                    for name, setup in setup_data.items():

                        for idx, elem in enumerate(
                            types
                        ):  # run scheme for any type, starting with singletons
                            valid = True
                            if meta["needs_authority"] == True and "auth" not in elem:
                                valid = False
                            if meta["needs_label"] == True and "lab" not in elem:
                                valid = False
                            if not valid:
                                continue
                            test_method = create_correctness_test_case(
                                meta, setup, scheme_path, idx
                            )
                            setattr(
                                unittest.TestCase,
                                f"test_CORRECTNESS-{name}-{elem}",
                                test_method,
                            )
                elif (
                    "conversion" in setup_file
                ):  # converter tests (tests/conversion.json)
                    for name, case in setup_data.items():
                        input_policy = case["input_policy"]
                        expected_policy_triple = case["expected_policy_triple"]
                        expected_policy_auth_tuple = case["expected_policy_auth_tuple"]
                        expected_policy_lab_tuple = case["expected_policy_lab_tuple"]
                        expected_policy_singleton = case["expected_policy_singleton"]
                        input_attributes = case["input_attributes"]
                        expected_attributes_triple = case["expected_attributes_triple"]
                        expected_attributes_auth_tuple = case[
                            "expected_attributes_auth_tuple"
                        ]
                        expected_attributes_lab_tuple = case[
                            "expected_attributes_lab_tuple"
                        ]
                        expected_attributes_singleton = case[
                            "expected_attributes_singleton"
                        ]

                        for idx, elem in enumerate(types):

                            if elem == "value":
                                expected_attributes = expected_attributes_singleton
                                expected_policy = expected_policy_singleton
                            elif elem == "auth.value":
                                expected_attributes = expected_attributes_auth_tuple
                                expected_policy = expected_policy_auth_tuple
                            elif elem == "lab:value":
                                expected_attributes = expected_attributes_lab_tuple
                                expected_policy = expected_policy_lab_tuple
                            elif elem == "auth.label:value":
                                expected_attributes = expected_attributes_triple
                                expected_policy = expected_policy_triple

                            test_method = create_typeconvert_test_case(
                                meta,
                                idx,
                                input_attributes,
                                input_policy,
                                expected_attributes,
                                expected_policy,
                            )
                            setattr(
                                unittest.TestCase,
                                f"test_CONVERSION-{name}-{elem}",
                                test_method,
                            )
            else:
                assert False, "wrong format"

    suite = unittest.TestLoader().loadTestsFromTestCase(unittest.TestCase)
    return suite


def create_correctness_test_case(meta, setup, scheme_path, idx):
    def test_method(self):
        correct = setup["correct"]
        test_setup = dict(setup)
        try:
            parser = parsing.ABEParser(meta)
            test_setup["attributes"], test_setup["policy"] = parser.convert_type(
                setup["attributes"], setup["policy"], idx
            )

            result = template.main(meta, test_setup, scheme_path)
            assert (
                result == correct
            ), f"[FAILED] Scheme should have passed for option {idx}"

        except AssertionError as e:
            if correct:
                raise Exception(e) from None
            # else:
            #    print(f"[CORRECT] {e}")

    return test_method


def create_typeconvert_test_case(
    meta, idx, input_attributes, input_policy, expected_attributes, expected_policy
):
    def test_method(self):
        try:
            parser = parsing.ABEParser(meta)
            result_attributes, result_policy = parser.convert_type(
                input_attributes, input_policy, idx
            )
            assert (
                result_attributes == expected_attributes
            ), f"[FAILED] Expected: {expected_attributes} Result: {result_attributes}"
            assert (
                result_policy == expected_policy
            ), f"[FAILED] Expected: {expected_policy} Result: {result_policy}"

        except AssertionError as e:
            raise

    return test_method


def create_tau_test_case(meta, setup):
    def test_method(self):

        parser = parsing.ABEParser(meta)
        policy = setup["policy"]
        expected_tau = setup["expected_tau"]
        pattern, type_name = parser.get_policy_type(policy)
        raw_attributes = parser.policy_extract_splitted(policy, pattern)
        attributes = [
            parser.splitted_to_attribute(attribute, type_name)
            for attribute in raw_attributes
        ]
        result_tau = parser.extract_tau(attributes)
        assert (
            result_tau == expected_tau
        ), f"[FAILED] \n Expected: {expected_tau} \n Result: {result_tau}"

    return test_method


##############################
