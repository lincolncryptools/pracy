"""
Please refer to the documentation provided
"""

from CharmBackend import datastructures, calculations, parsing


class Scheme:
    def __init__(self, meta_data, ir_path, group_obj, user):
        """ """
        global meta, folder, calc

        meta = meta_data
        folder = ir_path

        self.calc_instance = calculations.Calculations(group_obj, meta)
        calc = self.calc_instance

    def setup(self, AUTHORITIES, ATTRIBUTE_UNIVERSE=None):
        """initializes MSK & MPK and modifies them by calculations of setup.gen"""
        MSK = datastructures.MasterSecretKey()
        MPK = datastructures.MasterPublicKey()
        context = {
            "AUTHORITIES": AUTHORITIES,
            "MSK": MSK,
            "MPK": MPK,
            "ATTRIBUTE_UNIVERSE": ATTRIBUTE_UNIVERSE,
        }

        calc.execute_scheme(f"{folder}setup.gen", context)

        return (MSK, MPK)

    def keygen(self, MSK, y):
        """initializes SK and modifies it by calculations of keygen.gen"""
        SK = datastructures.SecretKey()

        if meta["abe-type"] == "CP-ABE":
            SK["y"] = datastructures.Set(
                original=y, elements=calc.attributes_to_elements(y)
            )
        elif meta["abe-type"] == "KP-ABE":
            SK["y"] = datastructures.Set(
                original=y, elements=calc.policy_to_literals(y)
            )
        else:
            assert False, "No abe type given"

        context = {
            "non_lone_randoms": {},
            "lone_randoms": {},
            "keygen_local_vars": {},
            "USER_ATTRIBUTES": SK["y"].elements,
            "SK": SK,
            "MSK": MSK,
        }

        calc.execute_scheme(f"{folder}keygen.gen", context)
        calc.check_object(SK)

        return SK

    def encrypt(self, MPK, x, M):
        """initializes CT and modifies it by calculations of encrypt.gen"""
        CT = datastructures.Ciphertext()

        if meta["abe-type"] == "CP-ABE":
            pols = calc.process_policy(x)
            CT["x"] = datastructures.Policy(
                original=pols[0],
                lsss_friendly=pols[1],
                charm_lsss=pols[2],
                literals=pols[3],
            )
            LSSS_map = {
                literal.index: literal for literal in CT["x"].literals
            }  # {0: Literal(), 1: Literal(),...}
            LSSS_ROWS = list(
                set([literal.index for literal in CT["x"].literals])
            )  # [0, 1]
            DEDUPLICATION_INDICES = list(
                set([literal.tau for literal in CT["x"].literals])
            )
        elif meta["abe-type"] == "KP-ABE":
            CT["x"] = datastructures.Policy(
                original=x,
                literals=calc.attributes_to_elements(y),
            )
            LSSS_map = {
                literal.index: literal for literal in CT["x"].literals
            }  # {0: Literal(), 1: Literal(),...}
            LSSS_ROWS = list(
                set([literal.index for literal in CT["x"].literals])
            )  # [0, 1]
            DEDUPLICATION_INDICES = list(
                set([literal.iota for literal in CT["x"].literals])
            )
        else:
            assert False, "No ABE-type given"

        context = {
            "lone_randoms": {},
            "non_lone_randoms": {},
            "special_lone_randoms": {},
            "encrypt_local_vars": {},
            "LSSS_map": LSSS_map,
            "LSSS_ROWS": LSSS_ROWS,
            "CT": CT,
            "DEDUPLICATION_INDICES": DEDUPLICATION_INDICES,
            "MPK": MPK,
            "M": M,
        }

        calc.execute_scheme(f"{folder}encrypt.gen", context)
        acc_gt = context.get("acc_gt")
        CT["C"] = acc_gt * M
        calc.check_object(CT)
        return CT

    def decrypt(self, MPK, x, y):
        """calculates PT by calculations of decrypt.gen"""
        context = {
            "acc_gt": calc.initialize_gt(1),
            "LSSS_map": {literal.index: literal for literal in x["x"].literals},
            "LINEAR_COMB_INDICES": calc.check_prune(y["y"].elements, x["x"]),
            "CT": x,
            "SK": y,
        }
        calc.execute_scheme(f"{folder}decrypt.gen", context)

        acc_gt = context.get("blinding_poly")
        M = x["C"] * (acc_gt ** (-1))
        calc.check_group_membership("gt", M)

        return M


def main(meta, setup, ir_path):
    """ """
    # check if setup is valid
    parsing.setup_handler(meta, setup)
    user = setup["user"]
    group_opj = setup["groupObj"]
    policy_string = setup["policy"]
    user_attributes = setup["attributes"]
    attribute_universe = setup["attribute_universe"]
    authorities = setup["authorities"]

    scheme = Scheme(meta_data=meta, ir_path=ir_path, group_obj=group_opj, user=user)
    # Setup
    if meta["attribute-universe"] == "small":
        (MSK, MPK) = scheme.setup(authorities, attribute_universe)
    elif meta["attribute-universe"] == "large":
        (MSK, MPK) = scheme.setup(authorities)
    else:
        raise Exception("attribute-universe in meta.json doesnt match CP-/KP-ABE")

    # KeyGen / Encryption
    M = scheme.calc_instance.sample_gt()
    if meta["abe-type"] == "CP-ABE":
        SK = scheme.keygen(MSK, user_attributes)
        CT = scheme.encrypt(MPK, policy_string, M)
    elif meta["abe-type"] == "KP-ABE":
        SK = scheme.keygen(MSK, policy_string)
        CT = scheme.encrypt(MPK, user_attributes, M)
    else:
        raise Exception("attribute-universe in meta.json doesnt match CP-/KP-ABE")

    # Decryption
    PT = scheme.decrypt(MPK, CT, SK)

    if M == PT:
        return True
    else:
        return False
