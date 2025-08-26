#include "abe_scheme.h"

Abe_scheme::Abe_scheme(Env env, Ops _ops) : _env(env), ops(_ops) { }

void Abe_scheme::setup(Master_secret_key& msk, Master_public_key& mpk) {
  Env env = this->_env;
  std::string idx = "";
#include "setup.gen"
}

void Abe_scheme::keygen(Master_secret_key& msk, User_attributes& user_attrs, User_secret_key& usk) {
  Env& env = this->_env;
  usk.user_attrs = user_attrs;
  std::map<std::string, Z> lone_randoms;
  std::map<std::string, Z> non_lone_randoms;
  Z tmp_z;
  Z aux_z;
  Z tmp_z_2;
  Z acc_z;
  G tmp_g;
  G acc_g;
  H tmp_h;
  H acc_h;
  std::string idx = "";
#include "keygen.gen"
}

void Abe_scheme::encrypt(Master_public_key& mpk, Policy& pol, Ciphertext& ct) {
  Env& env = this->_env;
  ct.policy = pol;
  std::map<std::string, Z> lone_randoms;
  std::map<std::string, Z> non_lone_randoms;
  std::map<std::string, Z> special_lone_randoms;
  Z tmp_z;
  Z aux_z;
  Z tmp_z_2;
  Z acc_z;
  G tmp_g;
  G acc_g;
  H tmp_h;
  H acc_h;
  Gt tmp_gt;
  Gt acc_gt;
  std::string idx = "";
#include "encrypt.gen"
}

bool Abe_scheme::decrypt(User_secret_key& usk, Ciphertext& ct, Gt& blinding_poly) {
  User_attributes user_attrs = usk.user_attrs;
  Policy policy = ct.policy;
  if (!policy.is_satisfied(user_attrs)) {
    return false;
  }
  Env& env = this->_env;
  Z tmp_z;
  Z aux_z;
  Z tmp_z_2;
  Z acc_z;
  G tmp_g;
  G acc_g;
  H tmp_h;
  H acc_h;
  Gt tmp_gt;
  Gt acc_gt;
  std::string idx = "";
#include "decrypt.gen"
  return true;
}
