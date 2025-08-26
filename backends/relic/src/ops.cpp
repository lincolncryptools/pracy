#include "ops.h"

extern "C" {
#include <relic/relic.h>
#include <relic/relic_pc.h>
}

Z Ops::sample_z() {
  bn_t order;                                                                                                        
  pc_get_ord(order);
  Z z;
  bn_rand_mod(z._data, order);
  return z;
}

Z Ops::one_z() {
  Z z;
  bn_set_bit(z._data, 0, 1);
  return z;
}

Z Ops::set_z(int val) {
  Z z;
  bn_set_dig(z._data, val);
  return z;
}

Z Ops::read_z(std::string str) {
  Z z;
  bn_read_str(z._data, str.c_str(), str.size(), 10);
  return z;
}

Z Ops::add_z(Z lhs, Z rhs) {
  Z z;
  bn_add(z._data, lhs._data, rhs._data);
  return z;
}

Z Ops::sub_z(Z lhs, Z rhs) {
  Z z;
  bn_sub(z._data, lhs._data, rhs._data);
  return z;
}

Z Ops::mul_z(Z lhs, Z rhs) {
  Z z;
  bn_mul(z._data, lhs._data, rhs._data);
  return z;
}

Z Ops::neg_z(Z arg) {
  Z zero;
  return this->sub_z(zero, arg);
}

Z Ops::inv_z(Z arg) {
  Z res;
  Z prime;
  pc_get_ord(prime._data);
  // It seems that bn_mod_inv is incorrect for negative numbers
  if (bn_sign(arg._data) == RLC_NEG) {
    bn_mod_basic(arg._data, arg._data, prime._data);
  }
  bn_mod_inv(res._data, arg._data, prime._data);
  return res;
}

Z Ops::scale_z(int lhs, Z rhs) {
  Z z = read_z(std::to_string(lhs));
  return mul_z(z, rhs);
}

Z Ops::reset_z() {
  Z z;
  return z;
}

G Ops::lift_g(Z z) {
  G g;
  g1_mul_gen(g._data, z._data);
  return g;
}

G Ops::scale_g(Z z, G g) {
  G r;
  g1_mul(r._data, g._data, z._data);
  return r;
}

G Ops::add_g(G g1, G g2) {
  G g;
  g1_add(g._data, g1._data, g2._data);
  return g;
}

G Ops::reset_g() {
  Z z;
  return this->lift_g(z);
}

G Ops::fdh_g(int idx, std::string arg) {
  std::string hash_key = std::to_string(idx) + ":" + arg;
  G g;
  g1_map(g._data, (const uint8_t*) hash_key.c_str(), hash_key.length());
  return g;
}

H Ops::lift_h(Z z) {
  H h;
  g2_mul_gen(h._data, z._data);
  return h;
}

H Ops::scale_h(Z z, H h) {
  H r;
  g2_mul(r._data, h._data, z._data);
  return r;
}

H Ops::add_h(H h1, H h2) {
  H h;
  g2_add(h._data, h1._data, h2._data);
  return h;
}

H Ops::reset_h() {
  Z z;
  return this->lift_h(z);
}

H Ops::fdh_h(int idx, std::string arg) {
  std::string hash_key = std::to_string(idx) + ":" + arg;
  H h;
  g2_map(h._data, (const uint8_t*) hash_key.c_str(), hash_key.length());
  return h;
}

Gt Ops::lift_gt(Z z) {
  Gt gt;
  gt_exp_gen(gt._data, z._data);
  return gt;
}

Gt Ops::scale_gt(Z z, Gt gt) {
  Gt r;
  gt_exp(r._data, gt._data, z._data);
  return r;
}

Gt Ops::add_gt(Gt gt1, Gt gt2) {
  Gt gt;
  gt_mul(gt._data, gt1._data, gt2._data);
  return gt;
}

Gt Ops::inv_gt(Gt gt) {
  Gt r;
  gt_inv(r._data, gt._data);
  return r;
}

Gt Ops::reset_gt() {
  Gt gt;
  return gt;
}

Gt Ops::pair(G g, H h) {
  Gt gt;
  pc_map(gt._data, g._data, h._data);
  return gt;
}
