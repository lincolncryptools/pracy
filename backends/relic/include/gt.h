#ifndef GT_H
#define GT_H

extern "C" {
#include <relic/relic.h>
#include <relic/relic_pc.h>
}

struct Gt {
  gt_t _data;

  Gt();
  ~Gt();
  Gt(const Gt& other);
  Gt& operator=(const Gt& other);

  void print();
  bool eq(const Gt& other);
  static Gt random();
};

#endif /* GT_H */
