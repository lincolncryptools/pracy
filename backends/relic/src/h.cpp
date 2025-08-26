#include "h.h"

H::H() {
  g2_null(_data);
  g2_new(_data);
}

H::~H() {
  g2_free(_data);
}

H::H(const H& other) {
  if (this != &other) {
    g2_copy(_data, other._data);
  }
}

H& H::operator=(const H& other) {
  if (this == &other) {
    return *this;
  }
  g2_copy(_data, other._data);
  return *this;
}

void H::print() {
  g2_print(_data);
}

bool H::eq(const H& other) {
  return g2_cmp(_data, other._data) == RLC_EQ;
}
