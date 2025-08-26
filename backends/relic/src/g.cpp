#include "g.h"

G::G() {
  g1_null(_data);
  g1_new(_data);
}

G::~G() {
  g1_free(_data);
}

G::G(const G& other) {
  if (this != &other) {
    g1_copy(_data, other._data);
  }
}

G& G::operator=(const G& other) {
  if (this == &other) {
    return *this;
  }
  g1_copy(_data, other._data);
  return *this;
}

void G::print() {
  g1_print(_data);
}

bool G::eq(const G& other) {
  return g1_cmp(_data, other._data) == RLC_EQ;
}
