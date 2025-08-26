#ifndef ABE_SCHEME_H
#define ABE_SCHEME_H

#include "abe_types.h"
#include "env.h"
#include "ops.h"

struct Abe_scheme {
  Abe_scheme(Env env, Ops _ops);
  void setup(Master_secret_key& msk, Master_public_key& mpk);
  void keygen(Master_secret_key& msk, User_attributes& user_attrs, User_secret_key& usk);
  void encrypt(Master_public_key& mpk, Policy& pol, Ciphertext& ct);
  bool decrypt(User_secret_key& usk, Ciphertext& ct, Gt& blinding_poly);

private:
  Env _env;
  Ops ops;
};

#endif /* ABE_SCHEME_H */
