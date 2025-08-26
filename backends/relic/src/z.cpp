#include <z.h>

Z::Z() {
  bn_new(_data);
  bn_null(_data);
  bn_set_dig(_data, 0);
}

Z::~Z() {
  bn_free(_data);
}

Z::Z(const Z& other) {
  if (this != &other) {
    bn_copy(_data, other._data);
  }
}

Z& Z::operator=(const Z& other) {
  if (this == &other) {
    return *this;
  }
  bn_copy(_data, other._data);
  return *this;
}

void Z::print() {
  bn_print(_data);
}
