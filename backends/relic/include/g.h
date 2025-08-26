#ifndef G_H
#define G_H

extern "C" {
#include <relic/relic.h>
#include <relic/relic_pc.h>
}

struct G {
  g1_t _data;

  G();
  ~G();
  G(const G& other);
  G& operator=(const G& other);

  void print();
  bool eq(const G& other);
};

#endif /* G_H */
