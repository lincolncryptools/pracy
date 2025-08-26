#ifndef ABE_OPS_H
#define ABE_OPS_H

#include <string>
#include <map>

#include "z.h"
#include "g.h"
#include "h.h"
#include "gt.h"

struct Ops {
  std::map<std::string, Z> fdhs;

  Z sample_z();
  Z one_z();
  Z set_z(int val);
  Z read_z(std::string str);
  Z add_z(Z lhs, Z rhs);
  Z sub_z(Z lhs, Z rhs);
  Z mul_z(Z lhs, Z rhs);
  Z neg_z(Z arg);
  Z inv_z(Z arg);
  Z scale_z(int lhs, Z rhs);
  Z reset_z();

  G lift_g(Z z);
  G scale_g(Z z, G g);
  G add_g(G g1, G g2);
  G reset_g();
  G fdh_g(int idx, std::string arg);

  H lift_h(Z z);
  H scale_h(Z z, H h);
  H add_h(H h1, H h2);
  H reset_h();
  H fdh_h(int idx, std::string args);

  Gt lift_gt(Z z);
  Gt scale_gt(Z z, Gt gt);
  Gt add_gt(Gt gt1, Gt gt2);
  Gt inv_gt(Gt gt);
  Gt reset_gt();

  Gt pair(G g, H h);
};

#endif /* ABE_OPS_H */
