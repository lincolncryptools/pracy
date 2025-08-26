"""
Please refer to the documentation provided
"""

from dataclasses import dataclass


@dataclass()
class Attribute:
    auth: str
    label: str
    value: str


@dataclass()
class Literal:
    attr_repr: Attribute
    tau: list
    neg: bool
    index: str


@dataclass()
class Element:
    attr_repr: Attribute
    iota: None


@dataclass()
class Set:
    original: [str]
    elements: [Element]


@dataclass()
class Policy:
    original: str
    lsss_friendly: str
    charm_lsss: str
    literals: [Literal]


class MasterSecretKey:
    def __init__(self):
        self.params = {"alpha": {}, "b": {}}

    def __getitem__(self, key):
        return self.params[key]

    def __setitem__(self, key, value):
        self.params[key] = value

    def __repr__(self):
        return f"MSK({self.params})"


class MasterPublicKey:
    def __init__(self):
        self.params = {"alpha": {}, "b_g": {}, "b_h": {}}

    def __getitem__(self, key):
        return self.params[key]

    def __setitem__(self, key, value):
        self.params[key] = value

    def __repr__(self):
        return f"MPK({self.params})"


class SecretKey:
    def __init__(self):
        self.params = {"y": {}, "r_g": {}, "r_h": {}, "k_g": {}, "k_h": {}}

    def __getitem__(self, key):
        return self.params[key]

    def __setitem__(self, key, value):
        self.params[key] = value

    def __repr__(self):
        return f"SK({self.params})"


class Ciphertext:
    def __init__(self):
        self.params = {
            "x": {},
            "C": {},
            "bold_s_g": {},
            "bold_s_h": {},
            "bold_C_g": {},
            "bold_C_h": {},
            "bold_C_prime": {},
        }

    def __getitem__(self, key):
        return self.params[key]

    def __setitem__(self, key, value):
        self.params[key] = value

    def __repr__(self):
        return f"CT({self.params})"
