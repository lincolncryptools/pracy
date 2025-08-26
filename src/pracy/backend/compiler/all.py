from pracy.backend.compiler.decrypt import compile_decrypt
from pracy.backend.compiler.encrypt import compile_encrypt
from pracy.backend.compiler.keygen import compile_keygen
from pracy.backend.compiler.setup import compile_setup


def compile(scheme):
    master_key_vars = scheme.master_key_vars
    common_vars = scheme.common_vars
    group_map = scheme.group_map
    fdh_map = scheme.fdh_map
    setup = compile_setup(master_key_vars, common_vars, group_map, fdh_map)

    key_lone_randoms = scheme.key_lone_randoms
    key_non_lone_randoms = scheme.key_non_lone_randoms
    key_polys = scheme.key_polys
    group_map = scheme.group_map
    keygen = compile_keygen(
        key_lone_randoms, key_non_lone_randoms, key_polys, group_map, fdh_map
    )

    cipher_lone_randoms = scheme.cipher_lone_randoms
    cipher_special_lone_randoms = scheme.cipher_special_lone_randoms
    cipher_non_lone_randoms = scheme.cipher_non_lone_randoms
    cipher_primaries = scheme.cipher_primaries
    cipher_secondaries = scheme.cipher_secondaries
    cipher_blinding = scheme.cipher_blinding
    group_map = scheme.group_map
    fdh_map = scheme.fdh_map
    encrypt = compile_encrypt(
        cipher_lone_randoms,
        cipher_special_lone_randoms,
        cipher_non_lone_randoms,
        cipher_primaries,
        cipher_secondaries,
        cipher_blinding,
        group_map,
        fdh_map,
    )

    singles = scheme.dec_singles
    pairs = scheme.dec_pairs
    var_type_map = scheme.var_type_map
    decrypt = compile_decrypt(singles, pairs, var_type_map, fdh_map)

    return setup, keygen, encrypt, decrypt
