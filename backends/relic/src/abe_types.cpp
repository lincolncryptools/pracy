#include "abe_types.h"

#include <algorithm>
#include <iostream>
#include <ops.h>

void Master_secret_key::print() {
  using namespace std;
  cout << "Master secret key:" << endl;
  cout << "  alphas:" << endl;
  for (auto [key, val] : alphas) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  common vars:" << endl;
  for (auto [key, val] : common_vars) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
}

void Master_public_key::print() {
  using namespace std;
  cout << "Master public key:" << endl;
  cout << "  alphas:" << endl;
  for (auto [key, val] : alphas) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  common vars (G):" << endl;
  for (auto [key, val] : common_vars_g) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  common vars (H):" << endl;
  for (auto [key, val] : common_vars_h) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
}

Entry::Entry(std::string str) {
  auth = str.substr(0, str.find("."));
  lbl = str.substr(str.find(".") + 1, str.find(":") - str.find(".") - 1);
  attr = str.substr(str.find(":") + 1);
}

void Entry::print() {
  std::cout << auth << "." << lbl << ":" << attr;
}

void User_attributes::add_attr(std::string str) {
  Entry entry = Entry(str);
  entries.push_back(entry);
}

bool User_attributes::has_attr(Entry entry) {
  for (size_t i = 0; i < entries.size(); ++i) {
    if (entries[i] == entry) {
      return true;
    }
  }
  return false;
}

void User_attributes::print() {
  std::cout << "[";
  for (size_t i = 0; i < entries.size(); ++i) {
    entries[i].print();
    if (i != entries.size() - 1) {
      std::cout << ", ";
    }
  }
  std::cout << "]" << std::endl;
}

bool operator==(Entry const &self, Entry const &other) {
  return self.auth == other.auth && self.lbl == other.lbl && self.attr == other.attr;
}

User_attributes User_attributes::random(size_t count) {
  if (count > 100) {
    throw std::invalid_argument("Backend supports at most 100 user attributes");
  }
  User_attributes attrs;
  for (size_t i = 0; i < count; ++i) {
    Entry entry;
    int c = 'A';
#ifdef MULTI_AUTH
      entry.auth = {(char) (c + (i / 26)), (char) (c + (i % 26))};
#else
      entry.auth = "AA";
#endif
    c = 'a';
    entry.lbl = {(char) (c + (i / 26)), (char) (c + (i % 26))};
    c = '0';
    entry.attr = {(char) (c + (i / 10)), (char) (c + (i % 10))};
    attrs.entries.push_back(entry);
  }
  return attrs;
}

void User_secret_key::print() {
  using namespace std;
  cout << "User secret key" << endl;
  cout << "  user attributes:" << endl;
  cout << "    ";
  user_attrs.print();
  cout << endl;
  cout << "  non-lone vars (G):" << endl;
  for (auto [key, val] : non_lone_vars_g) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  non-lone vars (H):" << endl;
  for (auto [key, val] : non_lone_vars_h) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  key polys (G):" << endl;
  for (auto [key, val] : polys_g) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  key polys (H):" << endl;
  for (auto [key, val] : polys_h) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
}

void Policy::print() {
  for (size_t i = 0; i < conjunction.size(); ++i) {
    for (size_t j = 0; j < negations.size(); ++j) {
      if (negations[j] == i) {
	std::cout << "!";
      }
    }
    conjunction[i].print();
    if (i != conjunction.size() - 1) {
      std::cout << " && ";
    }
  }
  std::cout << std::endl;
}

bool Policy::is_satisfied(User_attributes user_attrs) {
  for (size_t i = 0; i < conjunction.size(); ++i) {
    Entry curr = conjunction[i];
    bool is_negated = false;
    for (size_t j = 0; j < negations.size(); ++j) {
      if (negations[j] == i) {
        is_negated = true;
      }
    }
    if (is_negated) {
      // negative: user needs precisely one alternative
      size_t num_alts = 0;
      for (size_t j = 0; j < user_attrs.entries.size(); ++j) {
        if (user_attrs.entries[j].auth == curr.auth && user_attrs.entries[j].lbl == curr.lbl && user_attrs.entries[j].attr != curr.attr) {
          num_alts += 1;
        }
      }
      if (num_alts != 1) {
        return false;
      }
    } else {
      // positive: user needs attribute as is
      if (!user_attrs.has_attr(curr)) {
        return false;
      }
    }
  }
  return true;
}

std::pair<std::vector<Z>, std::vector<Z>> Policy::share_secret(Z secret, Ops ops) {
  std::vector<Z> lambdas;
  std::vector<Z> mus;
  Z ZERO;
  Z random_sum_lambda;
  Z random_sum_mu;

  lambdas.push_back(Z());
  mus.push_back(Z());

  for (size_t i = 1; i < conjunction.size(); ++i) {
    Z v = ops.sample_z();
    lambdas.push_back(ops.sub_z(ZERO, v));
    random_sum_lambda = ops.add_z(random_sum_lambda, v);

    Z v_prime = ops.sample_z();
    mus.push_back(ops.sub_z(ZERO, v_prime));
    random_sum_mu = ops.add_z(random_sum_mu, v_prime);
  }
  lambdas[0] = ops.add_z(secret, random_sum_lambda);
  mus[0] = random_sum_mu;
  return std::make_pair(lambdas, mus);
}

void Ciphertext::print() {
  using namespace std;
  cout << "Ciphertext" << endl;
  cout << "  policy:" << endl;
  cout << "    " << endl;
  policy.print();
  cout << "  non-lone vars (G):" << endl;
  for (auto [key, val] : non_lone_vars_g) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  non-lone vars (H):" << endl;
  for (auto [key, val] : non_lone_vars_h) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  primary polys (G):" << endl;
  for (auto [key, val] : primary_polys_g) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  primary polys (H):" << endl;
  for (auto [key, val] : primary_polys_h) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
  cout << "  secondary polys:" << endl;
  for (auto [key, val] : secondary_polys) {
    cout << "    " << key << " = ";
    val.print();
    cout << endl;
  }
}
