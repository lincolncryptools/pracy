#ifndef ENV_H
#define ENV_H

#include <string>
#include <vector>
#include <set>
#include <map>

#include "z.h"
#include "abe_types.h"

typedef std::string Auth;
typedef std::string Lbl;
typedef std::string Attr;

struct Env {
  Ops ops;
  std::vector<Entry> _policy;
  std::vector<size_t> _negs;
  std::vector<Entry> _user_attrs;
  std::set<Auth> _auths;
  std::set<Lbl> _lbls;
  std::set<Attr> _attr_uni;
  std::map<Attr, Auth> _attr_to_auth;
  std::map<Attr, Lbl> _attr_to_lbl;
  Z _secret;
  Z _rgid_g;
  Z _rgid_h;
  std::vector<Z> _lambdas;
  std::vector<Z> _mus;
  std::map<std::string, Z> _xattrs;

  Env(User_attributes attrs, Policy policy, Ops _ops);

  std::vector<Auth> get_authorities();
  std::vector<Attr> get_attribute_universe();
  std::vector<Attr> get_user_attributes();
  std::vector<Lbl> get_labels();
  std::vector<int> get_lsss_rows();
  std::vector<int> get_pos_lsss_rows();
  std::vector<int> get_neg_lsss_rows();
  std::vector<int> get_deduplication_idcs();
  std::vector<int> get_linear_combination_idcs();
  std::vector<int> get_positive_linear_combination_idcs();
  std::vector<int> get_negative_linear_combination_idcs();

  std::string auth_to_string(Auth auth);
  std::string attr_to_string(Attr attr);
  std::string lbl_to_string(Lbl lbl);
  std::string ls_row_to_string(int i);
  std::string dedup_idx_to_string(int i);

  Auth attr_to_auth(Attr attr);
  Lbl attr_to_lbl(Lbl attr);
  int ls_row_to_dedup_idx(int i);
  Auth ls_row_to_auth(int i);
  Lbl ls_row_to_lbl(int i);
  Attr ls_row_to_attr(int i);
  Attr ls_row_to_alt_attr(int i);

  G get_rgid_g();
  H get_rgid_h();
  Z get_secret();
  Z get_lambda(int);
  Z get_mu(int);
  Z get_epsilon(int);
  Z get_xattr(Attr attr);
  Z get_xattr_alt(int);
};

#endif /* ENV_H */
