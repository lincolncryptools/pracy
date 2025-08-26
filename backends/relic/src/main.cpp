#include <iostream>

#include "z.h"
#include "g.h"
#include "h.h"
#include "gt.h"

#include "env.h"
#include "ops.h"

#include "abe_types.h"

extern "C" {
#include <relic/relic.h>
#include <relic/relic_pc.h>
}

#include "abe_scheme.h"

extern "C" {
#include "benchmark.h"
}

bool check_correctness(bool use_negs) {
  User_attributes user_attrs = User_attributes::random(POLICY_LEN);
  Policy policy;

  if (use_negs) {
    User_attributes policy_attrs;
    std::vector<size_t> negs;
    for (size_t i = 0; i < POLICY_LEN; ++i) {
      negs.push_back(i);
      Entry alt_entry;
      alt_entry.auth = user_attrs.entries[i].auth;
      alt_entry.lbl = user_attrs.entries[i].lbl;
      alt_entry.attr = user_attrs.entries[i].attr + "_neg";
      policy_attrs.entries.push_back(alt_entry);
    }
    policy = Policy(policy_attrs, negs);
  } else {
    policy = Policy(user_attrs);
  }

  std::cout << "Checking correctness ..." << std::endl;
  std::cout << "\tAttribute set = ";
  user_attrs.print();
  std::cout << "\tPolicy = ";
  policy.print();
  std::cout << std::endl;

  Ops ops;
  Env env = Env(user_attrs, policy, ops);
  Abe_scheme scheme(env, ops);

  // Setup
  Master_secret_key msk;
  Master_public_key mpk;
  scheme.setup(msk, mpk);

  // Keygen
  User_secret_key usk;
  scheme.keygen(msk, user_attrs, usk);

  // Encrypt
  Ciphertext ct;
  scheme.encrypt(mpk, policy, ct);

  // Decrypt
  Gt blinding_poly;
  bool can_decrypt = scheme.decrypt(usk, ct, blinding_poly);
  bool decrypt_correct = ct.blinding_poly.eq(blinding_poly);

  return can_decrypt && decrypt_correct;
}

double bench_setup(timer* t) {
  User_attributes user_attrs = User_attributes::random(POLICY_LEN);
  Policy policy;

#ifdef OT_NEGS
  User_attributes policy_attrs;
  std::vector<size_t> negs;
  for (size_t i = 0; i < POLICY_LEN; ++i) {
    negs.push_back(i);
    Entry alt_entry;
    alt_entry.auth = user_attrs.entries[i].auth;
    alt_entry.lbl = user_attrs.entries[i].lbl;
    alt_entry.attr = user_attrs.entries[i].attr + "_neg";
    policy_attrs.entries.push_back(alt_entry);
  }
  policy = Policy(policy_attrs, negs);
#else
  policy = Policy(user_attrs);
#endif

  Ops ops;
  Env env = Env(user_attrs, policy, ops);
  Abe_scheme scheme(env, ops);

  Master_secret_key msk;
  Master_public_key mpk;
  start_timer(t);
  scheme.setup(msk, mpk);
  return stop_timer(t);
}

double bench_keygen(timer* t) {
  User_attributes user_attrs = User_attributes::random(POLICY_LEN);
  Policy policy;

#ifdef OT_NEGS
  User_attributes policy_attrs;
  std::vector<size_t> negs;
  for (size_t i = 0; i < POLICY_LEN; ++i) {
    negs.push_back(i);
    Entry alt_entry;
    alt_entry.auth = user_attrs.entries[i].auth;
    alt_entry.lbl = user_attrs.entries[i].lbl;
    alt_entry.attr = user_attrs.entries[i].attr + "_neg";
    policy_attrs.entries.push_back(alt_entry);
  }
  policy = Policy(policy_attrs, negs);
#else
  policy = Policy(user_attrs);
#endif

  Ops ops;
  Env env = Env(user_attrs, policy, ops);
  Abe_scheme scheme(env, ops);

  Master_secret_key msk;
  Master_public_key mpk;
  scheme.setup(msk, mpk);

  User_secret_key usk;
  start_timer(t);
  scheme.keygen(msk, user_attrs, usk);
  return stop_timer(t);
}

double bench_encrypt(timer* t) {
  User_attributes user_attrs = User_attributes::random(POLICY_LEN);
  Policy policy;

#ifdef OT_NEGS
  User_attributes policy_attrs;
  std::vector<size_t> negs;
  for (size_t i = 0; i < POLICY_LEN; ++i) {
    negs.push_back(i);
    Entry alt_entry;
    alt_entry.auth = user_attrs.entries[i].auth;
    alt_entry.lbl = user_attrs.entries[i].lbl;
    alt_entry.attr = user_attrs.entries[i].attr + "_neg";
    policy_attrs.entries.push_back(alt_entry);
  }
  policy = Policy(policy_attrs, negs);
#else
  policy = Policy(user_attrs);
#endif

  Ops ops;
  Env env = Env(user_attrs, policy, ops);
  Abe_scheme scheme(env, ops);

  Master_secret_key msk;
  Master_public_key mpk;
  scheme.setup(msk, mpk);

  User_secret_key usk;
  scheme.keygen(msk, user_attrs, usk);

  Ciphertext ct;

  start_timer(t);
  scheme.encrypt(mpk, policy, ct);
  return stop_timer(t);
}

double bench_decrypt(timer* t) {
  User_attributes user_attrs = User_attributes::random(POLICY_LEN);
  Policy policy;

#ifdef OT_NEGS
  User_attributes policy_attrs;
  std::vector<size_t> negs;
  for (size_t i = 0; i < POLICY_LEN; ++i) {
    negs.push_back(i);
    Entry alt_entry;
    alt_entry.auth = user_attrs.entries[i].auth;
    alt_entry.lbl = user_attrs.entries[i].lbl;
    alt_entry.attr = user_attrs.entries[i].attr + "_neg";
    policy_attrs.entries.push_back(alt_entry);
  }
  policy = Policy(policy_attrs, negs);
#else
  policy = Policy(user_attrs);
#endif

  Ops ops;
  Env env = Env(user_attrs, policy, ops);
  Abe_scheme scheme(env, ops);

  Master_secret_key msk;
  Master_public_key mpk;
  scheme.setup(msk, mpk);

  User_secret_key usk;
  scheme.keygen(msk, user_attrs, usk);

  Ciphertext ct;
  scheme.encrypt(mpk, policy, ct);

  Gt blinding_poly;
  start_timer(t);
  scheme.decrypt(usk, ct, blinding_poly);
  return stop_timer(t);
}

int main(void) {
  core_init();

  pc_param_set_any();
  pc_param_print();
  std::cout << "POLICY_LEN = " << POLICY_LEN << std::endl;
  std::cout << "BENCH_ITERS = " << BENCH_ITERS << std::endl;

#ifdef MULTI_AUTH
  std::cout << "MULTI_AUTH = true" << std::endl;
#else
  std::cout << "MULTI_AUTH = false" << std::endl;
#endif

#ifdef OT_NEGS
  std::cout << "OT_NEGS = true" << std::endl;
#else
  std::cout << "OT_NEGS = false" << std::endl;
#endif

  bool is_correct = check_correctness(false);

#ifdef OT_NEGS
  is_correct &= check_correctness(true);
#endif

  benchmark("SETUP", BENCH_ITERS, &bench_setup);
  benchmark("KEYGEN", BENCH_ITERS, &bench_keygen);
  benchmark("ENCRYPT", BENCH_ITERS, &bench_encrypt);
  benchmark("DECRYPT", BENCH_ITERS, &bench_decrypt);

  if (is_correct) {
    std::cout << "Decryption successful" << std::endl;
    return 0;
  } else {
    std::cout << "Decryption failed" << std::endl;
    return 1;
  }

}
