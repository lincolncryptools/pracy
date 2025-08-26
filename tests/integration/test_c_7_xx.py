import os
from pathlib import Path

from pracy.analysis.scheme import analyze_scheme
from pracy.backend.compiler.decrypt import compile_decrypt
from pracy.backend.compiler.encrypt import compile_encrypt
from pracy.backend.compiler.keygen import compile_keygen
from pracy.backend.compiler.setup import compile_setup
from pracy.backend.export.relic import Relic
from pracy.frontend.parsing import parse_json

_path_to_self = Path(os.path.realpath(__file__))
_scheme_name = _path_to_self.stem.removeprefix("test_")
_json_path = _path_to_self.parent.parent.parent / "schemes" / (_scheme_name + ".json")
with open(_json_path, "r") as file:
    _json_input = file.read()


def test_setup_full_integration():
    raw_scheme = parse_json(_json_input)
    scheme = analyze_scheme(raw_scheme)
    master_key_vars = scheme.master_key_vars
    common_vars = scheme.common_vars
    group_map = scheme.group_map
    fdh_map = scheme.fdh_map
    setup = compile_setup(master_key_vars, common_vars, group_map, fdh_map)
    received = Relic().export(setup)
    expected = """\
/* BEGIN SETUP */
idx = "";
idx += "alpha";
idx += "_{";
idx += "}";
msk.alphas[idx] = ops.sample_z();
mpk.alphas[idx] = ops.lift_gt(msk.alphas[idx]);
idx = "";
idx += "a";
idx += "_{";
idx += "}";
msk.common_vars[idx] = ops.sample_z();
mpk.common_vars_h[idx] = ops.lift_h(msk.common_vars[idx]);
for (Attr i : env.get_attribute_universe()) {
    idx = "";
    idx += "h";
    idx += "_{";
    idx += env.attr_to_string(i);
    idx += "}";
    msk.common_vars[idx] = ops.sample_z();
    mpk.common_vars_h[idx] = ops.lift_h(msk.common_vars[idx]);
}
/* END SETUP */"""
    assert received == expected


def test_keygen_full_integration():
    raw_scheme = parse_json(_json_input)
    scheme = analyze_scheme(raw_scheme)
    key_lone_randoms = scheme.key_lone_randoms
    key_non_lone_randoms = scheme.key_non_lone_randoms
    key_polys = scheme.key_polys
    group_map = scheme.group_map
    fdh_map = scheme.fdh_map
    keygen = compile_keygen(
        key_lone_randoms, key_non_lone_randoms, key_polys, group_map, fdh_map
    )
    received = Relic().export(keygen)
    expected = """\
/* BEGIN KEYGEN */
idx = "";
idx += "t";
idx += "_{";
idx += "}";
non_lone_randoms[idx] = ops.sample_z();
usk.non_lone_vars_g[idx] = ops.lift_g(non_lone_randoms[idx]);
tmp_z = ops.reset_z();
acc_z = ops.reset_z();
tmp_z = ops.read_z("1");
aux_z = ops.read_z("3");
tmp_z = ops.mul_z(tmp_z, aux_z);
idx = "";
idx += "alpha";
idx += "_{";
idx += "}";
tmp_z = ops.mul_z(tmp_z, msk.alphas[idx]);
acc_z = ops.add_z(acc_z, tmp_z);
tmp_z = ops.read_z("1");
aux_z = ops.read_z("3");
tmp_z = ops.mul_z(tmp_z, aux_z);
idx = "";
idx += "t";
idx += "_{";
idx += "}";
tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
idx = "";
idx += "a";
idx += "_{";
idx += "}";
tmp_z = ops.mul_z(tmp_z, msk.common_vars[idx]);
acc_z = ops.add_z(acc_z, tmp_z);
acc_g = ops.lift_g(acc_z);
idx = "";
idx += "k";
idx += "_{";
idx += "}";
usk.polys_g[idx] = acc_g;
for (Attr x : env.get_user_attributes()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "t";
    idx += "_{";
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "h";
    idx += "_{";
    idx += env.attr_to_string(x);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, msk.common_vars[idx]);
    acc_z = ops.add_z(acc_z, tmp_z);
    acc_g = ops.lift_g(acc_z);
    idx = "";
    idx += "k";
    idx += "_{";
    idx += env.attr_to_string(x);
    idx += "}";
    usk.polys_g[idx] = acc_g;
}
/* END KEYGEN */"""
    assert received == expected


def test_encrypt_full_integration():
    raw_scheme = parse_json(_json_input)
    scheme = analyze_scheme(raw_scheme)

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
    received = Relic().export(encrypt)
    expected = """\
/* BEGIN ENCRYPT */
for (int j : env.get_lsss_rows()) {
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    non_lone_randoms[idx] = ops.sample_z();
    ct.non_lone_vars_h[idx] = ops.lift_h(non_lone_randoms[idx]);
}
idx = "";
idx += "<secret>";
idx += "_{";
idx += "}";
non_lone_randoms[idx] = env.get_secret();
ct.non_lone_vars_h[idx] = ops.lift_h(non_lone_randoms[idx]);
for (int j : env.get_lsss_rows()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_h = ops.reset_h();
    acc_h = ops.reset_h();
    acc_h = ops.lift_h(acc_z);
    tmp_z = ops.read_z("1");
    aux_z = env.get_lambda(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    idx = "";
    idx += "a";
    idx += "_{";
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = ops.read_z("-1");
    tmp_z = ops.mul_z(tmp_z, aux_z);
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "h";
    idx += "_{";
    Attr j_local_0 = env.ls_row_to_attr(j);
    idx += env.attr_to_string(j_local_0);
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    idx = "";
    idx += "c";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    ct.primary_polys_h[idx] = acc_h;
}
tmp_z = ops.reset_z();
acc_z = ops.reset_z();
tmp_gt = ops.reset_gt();
acc_gt = ops.reset_gt();
acc_gt = ops.lift_gt(acc_z);
tmp_z = ops.read_z("1");
idx = "";
idx += "alpha";
idx += "_{";
idx += "}";
tmp_gt = mpk.alphas[idx];
aux_z = env.get_secret();
tmp_z = ops.mul_z(tmp_z, aux_z);
tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
acc_gt = ops.add_gt(acc_gt, tmp_gt);
ct.blinding_poly = acc_gt;
/* END ENCRYPT */"""
    assert received == expected


def test_decrypt_full_integration():
    raw_scheme = parse_json(_json_input)
    scheme = analyze_scheme(raw_scheme)

    singles = scheme.dec_singles
    pairs = scheme.dec_pairs
    var_type_map = scheme.var_type_map
    fdh_map = scheme.fdh_map

    decrypt = compile_decrypt(singles, pairs, var_type_map, fdh_map)
    received = Relic().export(decrypt)
    expected = """\
/* BEGIN DECRYPT */
idx = "";
idx += "k";
idx += "_{";
idx += "}";
tmp_g = usk.polys_g[idx];
idx = "";
idx += "<secret>";
idx += "_{";
idx += "}";
tmp_h = ct.non_lone_vars_h[idx];
tmp_gt = ops.pair(tmp_g, tmp_h);
tmp_z = ops.read_z("1");
aux_z = ops.read_z("3");
aux_z = ops.inv_z(aux_z);
tmp_z = ops.mul_z(tmp_z, aux_z);
tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
acc_gt = ops.add_gt(acc_gt, tmp_gt);
for (int j : env.get_linear_combination_idcs()) {
    idx = "";
    idx += "t";
    idx += "_{";
    idx += "}";
    tmp_g = usk.non_lone_vars_g[idx];
    idx = "";
    idx += "c";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_h = ct.primary_polys_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = ops.read_z("-1");
    tmp_z = ops.mul_z(tmp_z, aux_z);
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
for (int j : env.get_linear_combination_idcs()) {
    idx = "";
    idx += "k";
    idx += "_{";
    Attr j_local_0 = env.ls_row_to_attr(j);
    idx += env.attr_to_string(j_local_0);
    idx += "}";
    tmp_g = usk.polys_g[idx];
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_h = ct.non_lone_vars_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = ops.read_z("-1");
    tmp_z = ops.mul_z(tmp_z, aux_z);
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
blinding_poly = acc_gt;
/* END DECRYPT */"""
    assert received == expected
