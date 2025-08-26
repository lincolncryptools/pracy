"""
Please refer to the documentation provided
"""

from pyparsing import Word, Group, infixNotation, opAssoc, Forward
from pyparsing import Literal as PyLiteral
from CharmBackend.datastructures import Element, Literal, Attribute, Policy
from functools import reduce
import re
import json
import logging
from itertools import chain


class ABEParser:
    def __init__(self, meta_data):
        global meta, pattern_types
        meta = meta_data
        pattern_types = self.generate_types()

    ########## TYPE ##########
    def split_type(self, attribute):
        """splits any attribute type into list of properties and dividors
        Args:
            attribtue (str): raw literal

        Returns:
            list: split-up literal

        Example: split_type('1.ONE')
            >>> ['1', '.', 'ONE']
        """
        pattern = meta["pattern"]
        result = pattern.parseString(attribute).asList()
        return result

    def generate_types(self):
        """Generates all literal types with names and pyparse pattern
        Args:
            None

        Returns:
            dict: all types with type_name:pyparse_pattern

        Example:
            generate_types():
            >>> {'singleton': W:(abcd), ..., 'triple': {{{{W:(abcd...) "."} W:(abcd...)} ":"} W:(abcd...)}}
        """

        char_universe = meta["character_universe"]
        elem = Word(char_universe)
        dividors = meta["dividors"]
        types = {}

        for k, v in meta["types"].items():
            pattern = f"({'|'.join(map(re.escape, dividors))})"  # create pattern to match syntax from meta.json
            splitted = re.split(pattern, v["syntax"])  # split type.syntax into list
            pattern_type = [
                item if item in dividors else elem for item in splitted
            ]  # ['auth', 'attr'] -> ['auth', '.', 'attr']
            types[k] = reduce(lambda a, b: a + b, pattern_type)

        return types

    def _detect_type(self, string):
        """checks whether input policy is of type singleton, auth-tupel, lab-tupel or triple
        Args:
            string (str): raw literal

        Returns:
            tuple:
                pyparsind.And: pyparser pattern of given literal
                string: name of the type, i.e., singleton, auth-tup, etc.

        Example:
            get_type('1.ONE')
            >>> ({W:(abcd...) "." W:(abcd...)}, "auth-tup")
        """
        result = next(
            (
                (v, k)
                for k, v in reversed(list(pattern_types.items()))
                if v.searchString(string)
            ),
            None,
        )

        return result

    def get_attribute_type(self, attributes):
        """Returns type name of attributes and raises exception if they differ, gets name of type from meta.json
        Args:
            attributes (list): list of types
        Returns:
            str: name of literal type
        Example: get_attribute_type(['1.ONE', '2.TWO'])
            >>> 'auth-tup'
        """
        assert attributes, "attributes list is empty"
        cache = [self._detect_type(attribute)[1] for attribute in attributes]
        assert same_items(
            cache
        ), "attributes have different types, please check your input"
        return cache[0]  # check if attributes got same type

    def get_policy_type(self, policy):
        """Returns type of policy
        Args:
            policy (str): policy
        Returns:
            tuple: pyparsing pattern and literal name
        Example: get_policy_type('ONE AND TWO')
            >>> ({W:(abcd...)}, 'singleton')
        """
        assert policy, "policy string is empty"
        result = self._detect_type(policy)
        return result

    def get_type(self, attributes, policy):
        """gets type of attributes and policy and raises exception if they differ
        Args:
            attributes (list): original list of user attributes
            policy (str): original string policy
        Returns:
            str, str: pyparse pattern and name of used attribute representation
        Example: get_type([ONE, TWO], "ONE AND TWO")
            >>> W:(abcd...), singleton
        """
        attr_name = self.get_attribute_type(attributes)
        policy_type, policy_name = self.get_policy_type(policy)
        assert attr_name == policy_name, "Attributes and policy have different types"
        return policy_type, policy_name

    #############################

    ########## X TO Y ##########
    def splitted_to_attribute(self, item, type_name=None):
        """Converts list of split-up attributes to type Attribute()
        Args:
            item (list): list of splitted attributes from policy_extract_splitted()

        Returns:
            datastructure.Attribute

        Example: splitted_to_attribtue(['AUTH', '.', 'LAB', ':', 'VAL'])
            >>> Attribute(auth='AUTH',...,value='VAL')

        eval() - Read line from json file as actual code
                Attribute(auth=item[0], label=item[2], value=item[4])
            -> Attribute(auth='1', label='even', value='FOUR')
        """
        if type_name == None:
            type_name = meta["type_name"]
        result = eval(meta["types"][type_name]["handler"])
        return result

    def policy_to_lsss_friendly(self, policy, policy_literals):
        """Replaces every literal in a policy with its leaf index in the tree
        Args:
            policy_string (str): string of raw policy
            policy_literals (list): list of all attributes from policy, list elements are of type Literal()

        Returns:
            string: lsss-friendly policy

        Example:
            substitute_literals('(1.ONE) AND (2.TWO) and (1.THREE)')
            >>> '(0) AND (1) AND (2)'
        """
        pattern = meta["pattern"]
        counter = iter(range(0, len(policy_literals)))
        pattern.setParseAction(lambda tokens: str(next(counter)))
        lsss_policy = pattern.transformString(policy)

        return lsss_policy

    def string_to_attribute(self, string):
        """extracts data from string type and returns dataclass Attribute() containing the data
        Args:
            string (str): string of any type
        Returns:
            Attribtue: extracted info from string saved in dataclass attribute
        Example: string_to_attribute('(AUTH.LAB:VAL)')
            >>> Attribute(auth='AUTH',...,value='VAL')
        """
        pattern = meta["pattern"]
        no_brackets = remove_brackets(string)
        item = self.split_type(no_brackets)
        attribute = self.splitted_to_attribute(item)
        return attribute

    def policy_to_literals(self, policy):
        """extract all attributes of policy and saves them in a list of Literals
        Args:
            policy (str): 'original' policy of any types in string format
        Returns:
            list: list of literals
        Example: policy_to_literals('1.ONE or 2.TWO')
            >>> [Literal(attr_repr=(Attribute(...), ...)), Literal(attr_repr=(...), ...)]
        """
        pattern = meta["pattern"]
        raw_attributes = self.policy_extract_splitted(policy)
        attributes = [
            self.splitted_to_attribute(attribute) for attribute in raw_attributes
        ]
        literals = self.attributes_to_literal(attributes)
        return literals

    def attributes_to_literal(self, attribute_list):
        """converts list of Attribute()s to list of types Element()s
        Args:
            attribute_list (list): list with elements of type Attribute()
        Returns:
            list: list with elements of type Element()
        """
        randomizers = self.extract_tau(attribute_list)
        result = [
            Literal(attr_repr=attr, tau=randomizers[idx], neg=False, index=str(idx))
            for idx, attr in enumerate(attribute_list)
        ]

        return result

    def string_to_element(self, string):
        """Maps a raw literal to type Element
        !!! Note: Only takes attr values as input
        Args:
            string: raw literal
        Returns:
            Element
        Example: string_to_element('ONE')
            >>> Element(attr_repr=Attribute(auth=None, ..., value='ONE'), iota=None)
        """
        return Element(
            attr_repr=Attribute(auth=None, label=None, value=string), iota=None
        )

    def attribute_to_element(self, attribute):
        """Maps type Attribtue() to type Element()
        Args:
            attribute: type Attribute()
        Returns:
            Element
        Example: attribute_to_element(Attribute(auth='1', ..., value='ONE'))
            >>> Element(attr_repr=Attribute(auth='1', ..., value='ONE'), iota=None)
        """
        return Element(attr_repr=attribute, iota=None)

    #############################

    ########## EXTRACTOR ##########
    def extract_group(self, input_string):
        splitted = re.split(r"\.", input_string)
        match = re.search(r"[^_]*$", splitted[0])
        if match:
            value = match.group(0)
            if value in {"g", "h", "gt"}:
                return value
        return None

    def extract_tau(self, attributes):
        """Assumption: max(|Attribut duplicates|) = |randomizers|
        Args:
            attributes (list): list of attributes of type Attribute()

        Returns:
            dictionary: dict of 'randomizers' as keys and its deduplicated attributes as values in a list

        Example:
            >>> extract_tau(ONE, TWO, THREE, ONE, ONE, TWO)
            [rand_0, rand_0, rand_0, rand_1, rand_2, rand_2]
        """

        tau = "ATTR"
        tau_tilde = "AUTH.LAB"

        # tau = meta['tau']
        # if any(dividor in tau for dividor in meta['dividors']):

        if tau == "ATTR":
            to_randomize = [attribute.value for attribute in attributes]
        elif tau == "AUTH.LAB":
            to_randomize = [
                f"{attribute.auth}.{attribute.label}" for attribute in attributes
            ]
        else:
            print("No tau from meta.json given")

        tracker = {}
        randomizers = []

        for item in to_randomize:
            count = tracker.get(item, 0)
            randomizers.append(count)
            tracker[item] = count + 1

        return randomizers

    def extract_negation(policy):
        print("TODO")

    def policy_extract_splitted(self, policy, pattern=None):
        """Splits policy into nested list with each attribute as sublist with elements
        Args:
            policy (str): raw policy
        Returns:
            list: splitted policy into list
        Example: policy_extract_splitted('(1.ONE) AND (2.TWO)')
            >>> [(['1', '.', 'ONE'], {}), (['2', '.', 'TWO'], {})]
        """
        if pattern == None:
            pattern = meta["pattern"]
        result = list(pattern.searchString(policy))

        return result

    def extract_auth_from_policy(self, policy):
        raw_attributes = self.policy_extract_splitted(policy)
        auths = [attr[0] for attr in raw_attributes]
        return auths

    def extract_auth_from_attr(self, attributes):
        raw_attributes = [self.split_type(attr) for attr in attributes]
        auths = [attr[0] for attr in raw_attributes]
        return auths

    #############################

    ########## CONVERT ##########
    def convert_type(self, attributes, policy, option):
        """
        Args:
            attributes
            policy
            option:
                0 - attribute
                1 - auth.attribute
                2 - lab:attribute
                3 - auth.label:attribute

        Returns:
            attributes
            policy

        WORKING CASES
            A.B -> A
            B:C -> A
            A.B:C -> A.B
                    -> B:C
                    -> A
        """
        used_type, used_type_name = self.get_type(attributes, policy)
        char_universe = meta["character_universe"]
        elem = Word(char_universe)
        dividors = meta["dividors"]
        operators = meta["operators"]
        pattern_names = list(pattern_types.keys())

        # NOT WORKING CASES
        if (
            used_type_name == pattern_names[0] and option == 0
        ):  # Singletons already in use
            return attributes, policy
        elif (
            used_type_name == pattern_names[0] and option != 0
        ):  # Cannot convert singeltons to something else
            return [], ""
        elif (
            used_type_name == pattern_names[1] and option == 1
        ):  # Lab-Tupels already in use
            return attributes, policy
        elif (
            used_type_name == pattern_names[1] and option > 1
        ):  # Lab-Tupels can only be converted to singletons
            return [], ""
        elif (
            used_type_name == pattern_names[2] and option == 1
        ):  # Auth-Tupels cannot be converted to Lab-Tuples
            return [], ""
        elif (
            used_type_name == pattern_names[2] and option == 2
        ):  # Auth-Tupels already in use
            return attributes, policy
        elif (
            used_type_name == pattern_names[2] and option == 3
        ):  # Auth-Tupels cannot be converted to triples
            return [], ""
        elif (
            used_type_name == pattern_names[3] and option == 3
        ):  # Triples already in use
            return attributes, policy

        # Policy
        expr = Forward()
        operand = (
            Group(pattern_types["triple"])
            | Group(pattern_types["auth-tup"])
            | Group(pattern_types["lab-tup"])
            | Group(pattern_types["singleton"])
        )
        expr <<= infixNotation(
            operand, [(PyLiteral(op), 2, opAssoc.LEFT) for op in operators]
        )
        result = expr.parseString(policy)  # returns nested list
        parsed = result[0].asList()

        # Policy
        converted_policy = transform_nested_policy(
            parsed, used_type_name, pattern_names, option
        )

        # Attributes
        l = []
        for elem in attributes:
            stripped = elem.strip("()")
            parsed = pattern_types[used_type_name].parseString(stripped, parseAll=True)
            if used_type_name == pattern_names[1] and option == 0:
                l.append(parsed[-1])
            elif used_type_name == pattern_names[2] and option == 0:
                l.append(parsed[-1])
            elif used_type_name == pattern_names[3] and option == 0:
                l.append(parsed[-1])
            elif used_type_name == pattern_names[3] and option == 1:
                l.append(f"{parsed[0]}.{parsed[-1]}")
            elif used_type_name == pattern_names[3] and option == 2:
                l.append(f"{parsed[2]}:{parsed[-1]}")
            else:
                raise ValueError("Invalid input")

        return l, converted_policy

    #############################


def transform_nested_policy(lst, used_type_name, pattern_names, option):
    """helper function for convert_type()"""
    result = []

    for element in lst:
        if isinstance(element, tuple) or (
            isinstance(element, list) and all(isinstance(item, str) for item in element)
        ):
            if used_type_name == pattern_names[1] and option == 0:
                result.append(f"({''.join(element[-1])})")
            elif used_type_name == pattern_names[2] and option == 0:
                result.append(f"({''.join(element[-1])})")
            elif used_type_name == pattern_names[3] and option == 0:
                result.append(f"({''.join(element[-1])})")
            elif used_type_name == pattern_names[3] and option == 1:
                result.append(f"({''.join(element[0])}.{element[-1]})")
            elif used_type_name == pattern_names[3] and option == 2:
                result.append(f"({''.join(element[2])}:{element[-1]})")
            else:
                return " ".join(result)
                raise ValueError("Please choose a correct pattern to convert to")

        elif isinstance(element, list):
            result.append(
                f"({transform_nested_policy(element, used_type_name, pattern_names, option)})"
            )
        else:
            result.append(str(element))

    return " ".join(result)


########## JSON ##########
def parse_json(file):
    """takes file path as input and converts data from json file to a dictionary
    Args:
        file (str): path to file
    Returns:
        dict: json data parsed as dict
    Example: parse_json('test.json')
        >>> {"test": true}
    """
    with open(file) as file_json:
        file_data = json.load(file_json)
    if isinstance(file_data, list):
        return file_data
    stack = [(file_data, {})]
    result = stack[0][1]

    while stack:
        current_data, current_result = stack.pop()
        for k, v in current_data.items():
            if isinstance(v, dict):
                current_result[k] = {}
                stack.append((v, current_result[k]))
            else:
                current_result[k] = v
    return result


##############################


########## HELPER ##########
def setup_handler(meta, setup):
    """checks the validity of the setup
    Args:
        meta
        setup

    Returns:
        None
    """
    parser = ABEParser(meta)
    auths = setup["authorities"]
    attr = setup["attributes"]
    pol = setup["policy"]

    # analyze
    (meta["pattern"], meta["type_name"]) = parser.get_type(attr, pol)

    # check if authorities are valid
    if "." in attr[0]:
        policy_auths = parser.extract_auth_from_policy(pol)
        # attr_auths = parser.extract_auth_from_attr(attr)
        if not set(policy_auths).issubset(set(auths)):
            # print('Auths from policy not subset of auth universe')
            # return False
            assert False, "Authorities are not sufficient"


def same_items(l):
    """returns true if all list elements are the same
    Args:
        l (list): list with elements
    Returns:
        bool: true if list elements are the same, false if not
    Example: same_items([1, 1, 1, 2])
        >>> False
    """
    return len(set(l)) == 1


def remove_brackets(string):
    """Removes brackets [(, )] from a string
    Args:
        string (str): input string
    Returns:
        str: input string with removed opening and closing brackets
    Example: remove_brackets('(X)')
        >>> 'X'
    """
    return string.replace("(", "").replace(")", "")


def iterate_deepest(data):
    """iterates over nested dicts
    Args:
        data (datastruct): datastructure from datastructures.py (like SecretKey or Ciphertext)
    Returns:
        full key and value of nested dict
    Example: iterate_deepest({1: {2: {3: [4]}}})
        >>> '1_2_3.4'
    """

    def _recurse(obj, parent=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{parent}.{k}" if parent else k
                yield from _recurse(v, full)
        else:
            yield parent, obj

    yield from _recurse(data.params)


##############################
