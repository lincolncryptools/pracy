#include "gt.h"

Gt::Gt() {
  gt_null(_data);
  gt_new(_data);
  gt_set_unity(_data);
}

Gt::~Gt() {
  gt_free(_data);
}

Gt::Gt(const Gt& other) {
  if (this != &other) {
    gt_copy(_data, other._data);
  }
}

Gt& Gt::operator=(const Gt& other) {
  if (this == &other) {
    return *this;
  }
  gt_copy(_data, other._data);
  return *this;
}

void Gt::print() {
  gt_print(_data);
}

bool Gt::eq(const Gt& other) {
  return gt_cmp(_data, other._data) == RLC_EQ;
}

Gt Gt::random() {
  Gt r;
  gt_rand(r._data);
  return r;
}
