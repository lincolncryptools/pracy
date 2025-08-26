#include <stdexcept>

#include "env.h"

Env::Env(User_attributes attrs, Policy policy, Ops _ops) {
  this->ops = _ops;
  _policy = policy.conjunction;
  _negs = policy.negations;
  for (size_t i = 0; i < _policy.size(); ++i) {
    Entry entry = _policy[i];
    _auths.insert(entry.auth);
    _lbls.insert(entry.lbl);
    _attr_uni.insert(entry.attr);
    if (_attr_to_auth.count(entry.attr) > 0 && _attr_to_auth[entry.attr] != entry.auth) {
      throw std::invalid_argument("Conflicting attr->auth mapping");
    } else {
      _attr_to_auth[entry.attr] = entry.auth;
    }
    if (_attr_to_lbl.count(entry.attr) > 0 && _attr_to_lbl[entry.attr] != entry.lbl) {
      throw std::invalid_argument("Conflicting attr->lbl mapping");
    } else {
      _attr_to_lbl[entry.attr] = entry.lbl;
    }
  }
  _user_attrs = attrs.entries;
  for (size_t i = 0; i < _user_attrs.size(); ++i) {
    Entry entry = _user_attrs[i];
    _auths.insert(entry.auth);
    _lbls.insert(entry.lbl);
    _attr_uni.insert(entry.attr);
    if (_attr_to_auth.count(entry.attr) > 0 && _attr_to_auth[entry.attr] != entry.auth) {
      throw std::invalid_argument("Conflicting attr->auth mapping");
    } else {
      _attr_to_auth[entry.attr] = entry.auth;
    }
    if (_attr_to_lbl.count(entry.attr) > 0 && _attr_to_lbl[entry.attr] != entry.lbl) {
      throw std::invalid_argument("Conflicting attr->lbl mapping");
    } else {
      _attr_to_lbl[entry.attr] = entry.lbl;
    }
  }
  _secret = ops.sample_z();
  _rgid_g = ops.sample_z();
  _rgid_h = ops.sample_z();
  std::pair<std::vector<Z>, std::vector<Z>> shares = policy.share_secret(_secret, ops);
  _lambdas = shares.first;
  _mus = shares.second;
}

std::vector<std::string> Env::get_authorities() {
  std::vector<Auth> auths;
  std::copy(_auths.begin(), _auths.end(), std::back_inserter(auths));
  return auths;
}

std::vector<std::string> Env::get_attribute_universe() {
  std::vector<std::string> attrs;
  std::copy(_attr_uni.begin(), _attr_uni.end(), std::back_inserter(attrs));
  return attrs;
}

std::vector<std::string> Env::get_user_attributes() {
  std::vector<std::string> attrs;
  for (size_t i = 0; i < _user_attrs.size(); ++i) {
    std::string a = _user_attrs[i].attr;
    attrs.push_back(a);
  }
  return attrs;
}

std::vector<std::string> Env::get_labels() {
  std::vector<std::string> lbls;
  std::copy(_lbls.begin(), _lbls.end(), std::back_inserter(lbls));
  return lbls;
}

std::vector<int> Env::get_lsss_rows() {
  std::vector<int> rows;
  for (size_t i = 0; i < _policy.size(); ++i) {
    rows.push_back(i);
  }
  return rows;
}

std::vector<int> Env::get_pos_lsss_rows() {
  std::vector<int> rows;
  for (size_t i = 0; i < _policy.size(); ++i) {
    bool is_neg = false;
    for (size_t j = 0; j < _negs.size(); ++j) {
      if (_negs[j] == i) {
	      is_neg = true;
      }
    }
    if (!is_neg) {
      rows.push_back(i);
    }
  }
  return rows;
}

std::vector<int> Env::get_neg_lsss_rows() {
  std::vector<int> rows;
  for (size_t i = 0; i < _policy.size(); ++i) {
    bool is_neg = false;
    for (size_t j = 0; j < _negs.size(); ++j) {
      if (_negs[j] == i) {
	      is_neg = true;
      }
    }
    if (is_neg) {
      rows.push_back(i);
    }
  }
  return rows;
}

std::vector<int> Env::get_deduplication_idcs() {
  // For now all attributes are unique in all aspects
  return {1};
}

std::vector<int> Env::get_linear_combination_idcs() {
  std::vector<int> idcs;
  for (size_t i = 0; i < _policy.size(); ++i) {
    idcs.push_back(i);
  }
  return idcs;
}

std::vector<int> Env::get_positive_linear_combination_idcs() {
  std::vector<int> idcs;
  for (size_t i = 0; i < _policy.size(); ++i) {
    bool is_neg = false;
    for (size_t j = 0; j < _negs.size(); ++j) {
      if (_negs[j] == i) {
	      is_neg = true;
      }
    }
    if (!is_neg) {
      idcs.push_back(i);
    }
  }
  return idcs;
}

std::vector<int> Env::get_negative_linear_combination_idcs() {
  std::vector<int> idcs;
  for (size_t i = 0; i < _policy.size(); ++i) {
    bool is_neg = false;
    for (size_t j = 0; j < _negs.size(); ++j) {
      if (_negs[j] == i) {
	      is_neg = true;
      }
    }
    if (is_neg) {
      idcs.push_back(i);
    }
  }
  return idcs;
}

std::string Env::auth_to_string(Auth auth) {
  return auth;
}

std::string Env::attr_to_string(Attr attr) {
  return attr;
}

std::string Env::lbl_to_string(Lbl lbl) {
  return lbl;
}

std::string Env::ls_row_to_string(int i) {
  return std::to_string(i);
}

std::string Env::dedup_idx_to_string(int i) {
  return std::to_string(i);
}

std::string Env::attr_to_auth(Attr attr) {
  if (_attr_to_auth.count(attr) != 1) {
    throw std::invalid_argument("Cannot compute authority for unknown attribute");
  } else {
    return _attr_to_auth[attr];
  }
}

std::string Env::attr_to_lbl(std::string attr) {
  if (_attr_to_lbl.count(attr) != 1) {
    throw std::invalid_argument("Cannot compute label for unknown attribute");
  } else {
    return _attr_to_lbl[attr];
  }
}

int Env::ls_row_to_dedup_idx(int i) {
  // For now all possible attributes are unique in all aspects
  (void)i;
  return 1;
}

std::string Env::ls_row_to_auth(int i) {
  return _policy[i].auth;
}

std::string Env::ls_row_to_lbl(int i) {
  return _policy[i].lbl;
}

std::string Env::ls_row_to_attr(int i) {
  return _policy[i].attr;
}

std::string Env::ls_row_to_alt_attr(int j) {
  Auth auth = ls_row_to_auth(j);
  Lbl lbl = ls_row_to_lbl(j);
  Attr trgt = ls_row_to_attr(j);
  std::vector<Attr> alts;
  for (size_t i = 0; i < _user_attrs.size(); ++i) {
    Entry alt = _user_attrs[i];
    if (alt.auth == auth && alt.lbl == lbl && alt.attr != trgt) {
      alts.push_back(alt.attr);
    }
  }
  if (alts.size() != 1) {
    throw std::invalid_argument("No (unique) alternative attribute could be found");
  }
  return alts[0];
}

G Env::get_rgid_g() {
  return ops.lift_g(_rgid_g);
}

H Env::get_rgid_h() {
  return ops.lift_h(_rgid_h);
}

Z Env::get_secret() {
  return _secret;
}

Z Env::get_lambda(int i) {
  return _lambdas[i];
}

Z Env::get_mu(int i) {
  return _mus[i];
}

Z Env::get_epsilon(int i) {
  (void)i;
  return ops.read_z("1");
}

Z Env::get_xattr(Attr attr) {
  if (_xattrs.count(attr) == 1) {
    return _xattrs.at(attr);
  } else {
    Z r = ops.sample_z();
    _xattrs[attr] = r;
    return r;
  }
}

Z Env::get_xattr_alt(int j) {
  Auth auth = ls_row_to_auth(j);
  Lbl lbl = ls_row_to_lbl(j);
  Attr attr = ls_row_to_attr(j);

  std::vector<Entry> alternatives;
  for (size_t i = 0; i < _user_attrs.size(); ++i) {
    Entry entry = _user_attrs[i];
    if (entry.auth == auth && entry.lbl == lbl) {
      if (entry.attr != attr) {
	      alternatives.push_back(entry);
      } else {
	      throw std::invalid_argument("Negation is not satisfied as the attribute itself is present.");
      }
    }
  }

  if (alternatives.size() == 0) {
    throw std::invalid_argument("Negation is not satisfied as no alternative is present.");
  } else if (alternatives.size() > 1) {
    throw std::invalid_argument("Negation is not satisfied as OT negation only allow exactly one alternative.");
  }

  return get_xattr(alternatives[0].attr);
}
