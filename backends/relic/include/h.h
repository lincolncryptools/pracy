#ifndef H_H
#define H_H

extern "C" {
#include <relic/relic.h>
#include <relic/relic_pc.h>
}

struct H {
  g2_t _data;

  H();
  ~H();
  H(const H& other);
  H& operator=(const H& other);

  void print();
  bool eq(const H& other);
};

#endif /* H_H */
