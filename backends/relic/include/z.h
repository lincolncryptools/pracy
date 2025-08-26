#ifndef Z_H
#define Z_H

extern "C" {
#include <relic/relic_pc.h>
}

struct Z {
  bn_t _data;

  Z();
  ~Z();
  Z(const Z& other);
  Z& operator=(const Z& other);

  void print();
};

#endif /* Z_H */
