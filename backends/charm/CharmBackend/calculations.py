"""
Please refer to the documentation provided
"""

import random
import string
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.pairinggroup import PairingGroup, pair, G1, G2, GT, ZR
from CharmBackend import parsing, datastructures


class Calculations:

    def __init__(self, group_obj, meta):
        ABEnc.__init__(self)
        global util, abeparser, users
        self.group = PairingGroup(group_obj)
        util = SecretUtil(self.group)
        abeparser = parsing.ABEParser(meta)

        self.g = self.__get_generator(G1)
        self.h = self.__get_generator(G2)
        self.gt = pair(self.g, self.h)

        self.__secret_cache = None
        self.__rgid_cache = None
        self._masking_values = None
        self._shares = None
        self._coefficients = None

    def sample_z(self):
        return self.group.random(ZR)

    def set_z(self, value):
        return int(value)

    def reset_z(self):
        return int(0)

    def sample_gt(self):
        return self.group.random(GT)

    def initialize_gt(self, value):
        return self.group.init(GT, value)

    def pair_groups(self, g1, g2):
        return pair(g1, g2)

    def lift_g(self, exponent):
        return self.g**exponent

    def reset_g(self):
        return self.lift_g(0)

    def lift_h(self, exponent):
        return self.h**exponent

    def reset_h(self):
        return self.lift_h(0)

    def lift_gt(self, exponent):
        return self.gt**exponent

    def reset_gt(self):
        return self.initialize_gt(1)

    def fdh_g(self):
        print("TODO")

    def fdh_h(self):
        print("TODO")

    def __calc_random_id(self):
        """returns random 4-character long string"""
        return int("".join([random.choice(string.digits) for _ in range(4)]))

    def __calc_secret(self):
        """returns random group element"""
        return self.group.random()

    def __calc_rgid(self):
        """calls __calc_random_id to generate rgid"""
        return self.__calc_random_id()

    def __calc_coefficients(self, policy):
        """uses charms built-in function to calculate coefficients - needs CHARM POLICY"""
        self._coefficients = util.getCoefficients(policy)

    def __calc_shares(self, policy):
        """uses charms built-in function to calculate shares - needs CHARM POLICY"""
        self._shares = util.calculateSharesDict(self.get_secret(), policy)

    def __calc_maskingvalues(self, policy):
        """ """
        self._masking_values = util.calculateSharesDict(0, policy)

    def get_coefficient(self, attr):
        return self._coefficients.get(attr)

    def get_share(self, attr):
        return self._shares.get(attr)

    def get_maskingvalue(self, val):
        return self._masking_values.get(val)

    def get_secret(self):
        if self.__secret_cache is None:
            self.__secret_cache = self.__calc_secret()
        return self.__secret_cache

    def get_rgid_g(self):
        if self.__rgid_cache is None:
            self.__rgid_cache = self.__calc_rgid()
        return self.lift_g(self.__rgid_cache)

    def get_rgid_h(self):
        if self.__rgid_cache is None:
            self.__rgid_cache = self.__calc_rgid()
        return self.lift_h(self.__rgid_cache)

    def string_of_attribute(self, val):
        if isinstance(val, str):
            return str(val)
        elif isinstance(val, datastructures.Element) or isinstance(
            val, datastructures.Literal
        ):
            return val.attr_repr.value
        else:
            raise TypeError

    def string_of_label(self, val):
        if isinstance(val, str):
            return str(val)
        elif isinstance(val, datastructures.Element) or isinstance(
            val, datastructures.Literal
        ):
            return val.attr_repr.label
        else:
            raise TypeError

    def string_of_authority(self, val):
        if isinstance(val, str):
            return str(val)
        elif isinstance(val, datastructures.Element) or isinstance(
            val, datastructures.Literal
        ):
            return val.attr_repr.auth
        else:
            raise TypeError

    def map_attribute_to_authority(self, attribute):
        if isinstance(attribute, str):
            return str(attribute)
        elif isinstance(attribute, datastructures.Element) or isinstance(
            attribute, datastructures.Literal
        ):
            return attribute.attr_repr.auth
        else:
            raise TypeError

    def map_attribute_to_label(self, attribute):
        if isinstance(attribute, str):
            return str(attribute)
        elif isinstance(attribute, datastructures.Element) or isinstance(
            attribute, datastructures.Literal
        ):
            return attribute.attr_repr.label
        else:
            raise TypeError

    def check_prune(self, user_attributes, policy):
        """determine whether a given set of attributes satisfies the policy (...iff. P(x,y) = 1...)
        Args:
            user_attributes ([Element]): list of user attributes as element
            policy (Policy()): policy of type Policy()
        Returns:
            list: if user attributes fulfill policy it returns a list of attributes [Literals] that 
                  are needed do decrypt, otherwise it returns False
        Example:
            check_prune(['0', '3'], '(0 or 1) and (2 or 3)')
            >>> ['0', '3']
        """
        # iterate over all literal(policy) attributes and over all element(user) attributes
        # if they match, append Literal to the list
        # needed because user_attributes are of type Element() but we need Literal().index for prune
        attributes = []
        for literal in policy.literals:  # iterate over policy literals
            literal_attr = literal.attr_repr
            for element in user_attributes:  # iterate over user attributes
                element_attr = element.attr_repr
                if literal_attr == element_attr:
                    attributes.append(literal)

        attribute_indices = [
            literal.index for literal in attributes
        ]  # Literal(...) -> int, so it matches charms policy
        prune = util.prune(policy.charm_lsss, attribute_indices)
        assert prune, "Attributes do not fulfill policy"
        prune_transformed = [str(repr(idx)) for idx in prune]
        lin_comb = [
            literal.index
            for literal in attributes
            if literal.index in prune_transformed
        ]
        return lin_comb

    def process_policy(self, policy_original):
        """create all pol representations and precalulate all belonging values
        Args:
            policy_original (str): original policy as string
        Returns:
            list: original policy, policy with ints for leafs instead of attribtues, 
                  policy created by charm, attribtues from original policy
        """
        policy_literals = abeparser.policy_to_literals(policy_original)
        policy_lsss = abeparser.policy_to_lsss_friendly(
            policy_original, policy_literals
        )
        policy_charm = util.createPolicy(policy_lsss)
        self.__calc_maskingvalues(policy_charm)
        self.__calc_shares(policy_charm)
        self.__calc_coefficients(policy_charm)
        return [policy_original, policy_lsss, policy_charm, policy_literals]

    def attributes_to_elements(self, string_attributes):
        attributes = [
            abeparser.string_to_attribute(attribute) for attribute in string_attributes
        ]
        elements = [
            abeparser.attribute_to_element(attribute) for attribute in attributes
        ]
        return elements

    def check_object(self, obj):
        """iterate over an object from datastrcutures.py like SecretKey or 
           Ciphertext and check for every param if its element is actually member of assigned group
        Args:
            obj (datastructure.OBJ):
        Return:
            None
        """
        for k, v in parsing.iterate_deepest(obj):
            if "_" in k:
                group = abeparser.extract_group(k)
                if not group:
                    continue
                self.check_group_membership(group, v)

    def check_group_membership(self, group, element):
        """checks if an pairing element is element in assigned class, asserts if not
        Args:
            group (str): assigned group
            element (pairing.Element): assigned element
        Returns:
            None
        """
        if group == "g":
            assert element.type == G1, f"Element {element} does not belong to Group G1"
        elif group == "h":
            assert element.type == G2, f"Element {element} does not belong to Group G2"
        elif group == "gt":
            assert element.type == GT, f"Element {element} does not belong to Group GT"
        else:
            assert False, f"No group found matching {group}"

    def __get_generator(self, subgroup):
        """get generator, i.e., g or h \ {0, 1}
        Args:
            subgroup: g or h (from G1 or G2)
        Returns:
            generator of given subgroup
        """
        generator = self.group.random(subgroup)
        one = self.group.init(subgroup, 1)
        zero = self.group.init(subgroup, 0)
        while generator == one or generator == zero:
            generator = self.group.random()

        return generator

    def execute_scheme(self, file, context=None):
        """executes the .gen files and stores all variables in a dict
        Args:
            file (str): path to file that shall be executed
            context: namespace in which the ir code operates
        Returns:
            dict: context/namespace with updated variables/etc
        """
        context["self"] = self  # to execute functions in this class
        with open(file, "r") as ir:
            exec(ir.read(), context)

        return context
