#ifndef ABE_TYPES_H
#define ABE_TYPES_H

#include <map>
#include <string>
#include <vector>

#include "z.h"
#include "g.h"
#include "h.h"
#include "gt.h"
#include "ops.h"

struct Master_secret_key {
  std::map<std::string, Z> alphas;
  std::map<std::string, Z> common_vars;

  void print();
};

struct Master_public_key {
  std::map<std::string, Gt> alphas;
  std::map<std::string, G> common_vars_g;
  std::map<std::string, H> common_vars_h;

  void print();
};

struct Entry {
  std::string auth;
  std::string lbl;
  std::string attr;

  Entry() : auth(), lbl(), attr() {};
  Entry(std::string str);
  void print();

  friend bool operator==(Entry const& self, Entry const &other);
};

struct User_attributes {
  std::vector<Entry> entries;

  void add_attr(std::string attr);
  bool has_attr(Entry entry);
  static User_attributes random(size_t count);
  void print();
};

struct User_secret_key {
  User_attributes user_attrs;
  std::map<std::string, G> non_lone_vars_g;
  std::map<std::string, H> non_lone_vars_h;
  std::map<std::string, G> polys_g;
  std::map<std::string, H> polys_h;

  void print();
};

/* For now a Policy is always the conjunction of a given set of attributes */
struct Policy {
  std::vector<Entry> conjunction;
  std::vector<size_t> negations;

  Policy() : conjunction() {};
  Policy(User_attributes attrs) : conjunction(attrs.entries) {};
  Policy(User_attributes attrs, std::vector<size_t> negs) : conjunction(attrs.entries), negations(negs) {};

  void print();
  bool is_satisfied(User_attributes user_attrs);
  std::pair<std::vector<Z>, std::vector<Z>> share_secret(Z secret, Ops ops);
};

struct Ciphertext {
  Policy policy;
  std::map<std::string, G> non_lone_vars_g;
  std::map<std::string, H> non_lone_vars_h;
  std::map<std::string, G> primary_polys_g;
  std::map<std::string, H> primary_polys_h;
  std::map<std::string, Gt> secondary_polys;
  Gt blinding_poly;

  void print();
};

#endif /* ABE_TYPES_H */
