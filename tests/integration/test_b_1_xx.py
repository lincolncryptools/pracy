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
for (Auth l : env.get_authorities()) {
    idx = "";
    idx += "alpha";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    msk.alphas[idx] = ops.sample_z();
    mpk.alphas[idx] = ops.lift_gt(msk.alphas[idx]);
}
for (Auth l : env.get_authorities()) {
    idx = "";
    idx += "b";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    msk.common_vars[idx] = ops.sample_z();
    mpk.common_vars_h[idx] = ops.lift_h(msk.common_vars[idx]);
}
for (Auth l : env.get_authorities()) {
    idx = "";
    idx += "b'";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    msk.common_vars[idx] = ops.sample_z();
    mpk.common_vars_h[idx] = ops.lift_h(msk.common_vars[idx]);
}
for (Auth l : env.get_authorities()) {
    for (Lbl lab : env.get_labels()) {
        idx = "";
        idx += "b";
        idx += "_{";
        idx += env.auth_to_string(l);
        idx += ",";
        idx += env.lbl_to_string(lab);
        idx += ",";
        idx += "0";
        idx += "}";
        msk.common_vars[idx] = ops.sample_z();
        mpk.common_vars_h[idx] = ops.lift_h(msk.common_vars[idx]);
    }
}
for (Auth l : env.get_authorities()) {
    for (Lbl lab : env.get_labels()) {
        idx = "";
        idx += "b";
        idx += "_{";
        idx += env.auth_to_string(l);
        idx += ",";
        idx += env.lbl_to_string(lab);
        idx += ",";
        idx += "1";
        idx += "}";
        msk.common_vars[idx] = ops.sample_z();
        mpk.common_vars_h[idx] = ops.lift_h(msk.common_vars[idx]);
    }
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
for (Attr l_global : env.get_user_attributes()) {
    Auth l = env.attr_to_auth(l_global);
    idx = "";
    idx += "r";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    non_lone_randoms[idx] = ops.sample_z();
    usk.non_lone_vars_g[idx] = ops.lift_g(non_lone_randoms[idx]);
}
for (Attr l_global : env.get_user_attributes()) {
    Auth l = env.attr_to_auth(l_global);
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "alpha";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, msk.alphas[idx]);
    acc_z = ops.add_z(acc_z, tmp_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "r";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b'";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, msk.common_vars[idx]);
    acc_z = ops.add_z(acc_z, tmp_z);
    acc_g = ops.lift_g(acc_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "b";
    idx += "_{";
    idx += env.auth_to_string(l);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, msk.common_vars[idx]);
    tmp_g = env.get_rgid_g();
    tmp_g = ops.scale_g(tmp_z, tmp_g);
    acc_g = ops.add_g(acc_g, tmp_g);
    idx = "";
    idx += "k";
    idx += "_{";
    idx += "1";
    idx += ",";
    idx += env.auth_to_string(l);
    idx += "}";
    usk.polys_g[idx] = acc_g;
}
for (Attr att : env.get_user_attributes()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "r";
    idx += "_{";
    Auth att_local_0 = env.attr_to_auth(att);
    idx += env.auth_to_string(att_local_0);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth att_local_1 = env.attr_to_auth(att);
    idx += env.auth_to_string(att_local_1);
    idx += ",";
    Lbl att_local_2 = env.attr_to_lbl(att);
    idx += env.lbl_to_string(att_local_2);
    idx += ",";
    idx += "0";
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, msk.common_vars[idx]);
    acc_z = ops.add_z(acc_z, tmp_z);
    tmp_z = ops.read_z("1");
    aux_z = env.get_xattr(att);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    idx = "";
    idx += "r";
    idx += "_{";
    Auth att_local_3 = env.attr_to_auth(att);
    idx += env.auth_to_string(att_local_3);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth att_local_4 = env.attr_to_auth(att);
    idx += env.auth_to_string(att_local_4);
    idx += ",";
    Lbl att_local_5 = env.attr_to_lbl(att);
    idx += env.lbl_to_string(att_local_5);
    idx += ",";
    idx += "1";
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, msk.common_vars[idx]);
    acc_z = ops.add_z(acc_z, tmp_z);
    acc_g = ops.lift_g(acc_z);
    idx = "";
    idx += "k";
    idx += "_{";
    idx += "2";
    idx += ",";
    Lbl att_local_6 = env.attr_to_lbl(att);
    idx += env.lbl_to_string(att_local_6);
    idx += ",";
    idx += env.attr_to_string(att);
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
for (int j : env.get_lsss_rows()) {
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_0 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_0);
    idx += "}";
    non_lone_randoms[idx] = ops.sample_z();
    ct.non_lone_vars_h[idx] = ops.lift_h(non_lone_randoms[idx]);
}
for (int j : env.get_lsss_rows()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_h = ops.reset_h();
    acc_h = ops.reset_h();
    tmp_z = ops.read_z("1");
    aux_z = env.get_mu(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    acc_z = ops.add_z(acc_z, tmp_z);
    acc_h = ops.lift_h(acc_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "1";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += "}";
    ct.primary_polys_h[idx] = acc_h;
}
for (int j : env.get_pos_lsss_rows()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_h = ops.reset_h();
    acc_h = ops.reset_h();
    acc_h = ops.lift_h(acc_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b'";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_1 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_1);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth j_local_2 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_2);
    idx += ",";
    Lbl j_local_3 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_3);
    idx += ",";
    idx += "0";
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    tmp_z = ops.read_z("1");
    Attr x_attr_aux = env.ls_row_to_attr(j);
    aux_z = env.get_xattr(x_attr_aux);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_4 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_4);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth j_local_5 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_5);
    idx += ",";
    Lbl j_local_6 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_6);
    idx += ",";
    idx += "1";
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "2";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += ",";
    idx += "0";
    idx += "}";
    ct.primary_polys_h[idx] = acc_h;
}
for (int j : env.get_neg_lsss_rows()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_h = ops.reset_h();
    acc_h = ops.reset_h();
    acc_h = ops.lift_h(acc_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b'";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_1 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_1);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth j_local_2 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_2);
    idx += ",";
    Lbl j_local_3 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_3);
    idx += ",";
    idx += "1";
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "2";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += ",";
    idx += "1";
    idx += "}";
    ct.primary_polys_h[idx] = acc_h;
}
for (int j : env.get_neg_lsss_rows()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_h = ops.reset_h();
    acc_h = ops.reset_h();
    acc_h = ops.lift_h(acc_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_0 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_0);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth j_local_1 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_1);
    idx += ",";
    Lbl j_local_2 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_2);
    idx += ",";
    idx += "0";
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    tmp_z = ops.read_z("1");
    Attr x_attr_aux = env.ls_row_to_attr(j);
    aux_z = env.get_xattr(x_attr_aux);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_3 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_3);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    idx = "";
    idx += "b";
    idx += "_{";
    Auth j_local_4 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_4);
    idx += ",";
    Lbl j_local_5 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_5);
    idx += ",";
    idx += "1";
    idx += "}";
    tmp_h = mpk.common_vars_h[idx];
    tmp_h = ops.scale_h(tmp_z, tmp_h);
    acc_h = ops.add_h(acc_h, tmp_h);
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "3";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += "}";
    ct.primary_polys_h[idx] = acc_h;
}
for (int j : env.get_lsss_rows()) {
    tmp_z = ops.reset_z();
    acc_z = ops.reset_z();
    tmp_gt = ops.reset_gt();
    acc_gt = ops.reset_gt();
    tmp_z = ops.read_z("1");
    aux_z = env.get_lambda(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    acc_z = ops.add_z(acc_z, tmp_z);
    acc_gt = ops.lift_gt(acc_z);
    tmp_z = ops.read_z("1");
    idx = "";
    idx += "alpha";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_gt = mpk.alphas[idx];
    idx = "";
    idx += "s";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_z = ops.mul_z(tmp_z, non_lone_randoms[idx]);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
    idx = "";
    idx += "c'";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    ct.secondary_polys[idx] = acc_gt;
}
tmp_z = ops.reset_z();
acc_z = ops.reset_z();
tmp_gt = ops.reset_gt();
acc_gt = ops.reset_gt();
tmp_z = ops.read_z("1");
aux_z = env.get_secret();
tmp_z = ops.mul_z(tmp_z, aux_z);
acc_z = ops.add_z(acc_z, tmp_z);
acc_gt = ops.lift_gt(acc_z);
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
for (int j : env.get_linear_combination_idcs()) {
    tmp_z = ops.read_z("1");
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    idx = "";
    idx += "c'";
    idx += "_{";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_gt = ops.scale_gt(tmp_z, ct.secondary_polys[idx]);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
for (int j : env.get_linear_combination_idcs()) {
    idx = "";
    idx += "k";
    idx += "_{";
    idx += "1";
    idx += ",";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
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
for (int j : env.get_positive_linear_combination_idcs()) {
    idx = "";
    idx += "k";
    idx += "_{";
    idx += "2";
    idx += ",";
    Lbl j_local_0 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_0);
    idx += ",";
    Attr j_local_1 = env.ls_row_to_attr(j);
    idx += env.attr_to_string(j_local_1);
    idx += "}";
    tmp_g = usk.polys_g[idx];
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_2 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_2);
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
for (int j : env.get_negative_linear_combination_idcs()) {
    idx = "";
    idx += "k";
    idx += "_{";
    idx += "2";
    idx += ",";
    Lbl j_local_0 = env.ls_row_to_lbl(j);
    idx += env.lbl_to_string(j_local_0);
    idx += ",";
    Attr j_local_1 = env.ls_row_to_alt_attr(j);
    idx += env.attr_to_string(j_local_1);
    idx += "}";
    tmp_g = usk.polys_g[idx];
    idx = "";
    idx += "s'";
    idx += "_{";
    int j_local_2 = env.ls_row_to_dedup_idx(j);
    idx += env.dedup_idx_to_string(j_local_2);
    idx += "}";
    tmp_h = ct.non_lone_vars_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = ops.read_z("-1");
    tmp_z = ops.mul_z(tmp_z, aux_z);
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_z_2 = env.get_xattr_alt(j);
    Attr x_attr_aux = env.ls_row_to_attr(j);
    aux_z = env.get_xattr(x_attr_aux);
    aux_z = ops.neg_z(aux_z);
    aux_z = ops.add_z(tmp_z_2, aux_z);
    aux_z = ops.inv_z(aux_z);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
for (int j : env.get_linear_combination_idcs()) {
    tmp_g = env.get_rgid_g();
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "1";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_h = ct.primary_polys_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
for (int j : env.get_positive_linear_combination_idcs()) {
    idx = "";
    idx += "r";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_g = usk.non_lone_vars_g[idx];
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "2";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += ",";
    idx += "0";
    idx += "}";
    tmp_h = ct.primary_polys_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
for (int j : env.get_negative_linear_combination_idcs()) {
    idx = "";
    idx += "r";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_g = usk.non_lone_vars_g[idx];
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "2";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += ",";
    idx += "1";
    idx += "}";
    tmp_h = ct.primary_polys_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
for (int j : env.get_negative_linear_combination_idcs()) {
    idx = "";
    idx += "r";
    idx += "_{";
    Auth j_local_0 = env.ls_row_to_auth(j);
    idx += env.auth_to_string(j_local_0);
    idx += "}";
    tmp_g = usk.non_lone_vars_g[idx];
    idx = "";
    idx += "c";
    idx += "_{";
    idx += "3";
    idx += ",";
    idx += env.ls_row_to_string(j);
    idx += "}";
    tmp_h = ct.primary_polys_h[idx];
    tmp_gt = ops.pair(tmp_g, tmp_h);
    tmp_z = ops.read_z("1");
    aux_z = env.get_epsilon(j);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_z_2 = env.get_xattr_alt(j);
    Attr x_attr_aux = env.ls_row_to_attr(j);
    aux_z = env.get_xattr(x_attr_aux);
    aux_z = ops.neg_z(aux_z);
    aux_z = ops.add_z(tmp_z_2, aux_z);
    aux_z = ops.inv_z(aux_z);
    tmp_z = ops.mul_z(tmp_z, aux_z);
    tmp_gt = ops.scale_gt(tmp_z, tmp_gt);
    acc_gt = ops.add_gt(acc_gt, tmp_gt);
}
blinding_poly = acc_gt;
/* END DECRYPT */"""
    assert received == expected
