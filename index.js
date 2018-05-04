var sodium = require('sodium-native')
var assert = require('nanoassert')

module.exports = {
  init,
  commit,
  open,
  addCommitments,
  addDecommitments,

  PARAM_BYTES: sodium.crypto_scalarmult_ed25519_BYTES,
  COMMITMENT_BYTES: sodium.crypto_scalarmult_ed25519_BYTES,
  DATA_BYTES: sodium.crypto_scalarmult_ed25519_SCALARBYTES,
  RBYTES: sodium.crypto_scalarmult_ed25519_SCALARBYTES
}

var rnd = sodium.sodium_malloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
function init (out) {
  assert(out.byteLength === sodium.crypto_scalarmult_ed25519_BYTES)

  sodium.randombytes_buf(rnd)
  sodium.crypto_core_ed25519_from_uniform(out, rnd)
  assert(sodium.crypto_core_ed25519_is_valid_point(out))
  sodium.sodium_memzero(rnd)
}

var xG = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_BYTES)
var rH = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_BYTES)
function commit (commitment, r, x, H, rr) {
  assert(commitment.byteLength === sodium.crypto_scalarmult_ed25519_BYTES)
  assert(r.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(x.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(H.byteLength === sodium.crypto_scalarmult_ed25519_BYTES)
  assert(sodium.sodium_is_zero(x, x.byteLength) === false)
  assert(sodium.crypto_core_ed25519_is_valid_point(H))

  sodium.crypto_scalarmult_ed25519_base(xG, x)
  assert(sodium.crypto_core_ed25519_is_valid_point(xG))
  if (!rr) {
    sodium.randombytes_buf(r)
    r[0] = 0
    r[31] = 0
  }
  else r.set(rr)
  sodium.crypto_scalarmult_ed25519(rH, r, H)
  assert(sodium.crypto_core_ed25519_is_valid_point(rH))
  sodium.crypto_core_ed25519_add(commitment, xG, rH)
  sodium.sodium_memzero(xG)
  sodium.sodium_memzero(rH)
  assert(sodium.crypto_core_ed25519_is_valid_point(commitment))
}

var c = sodium.sodium_malloc(sodium.crypto_core_ed25519_BYTES)
function open (commitment, r, x, H) {
  assert(commitment.byteLength === sodium.crypto_scalarmult_ed25519_BYTES)
  assert(r.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(x.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(H.byteLength === sodium.crypto_scalarmult_ed25519_BYTES)
  // assert(sodium.crypto_core_ed25519_is_valid_point(commitment))
  assert(sodium.crypto_core_ed25519_is_valid_point(H))
  assert(sodium.sodium_is_zero(r, r.byteLength) === false, 'r must be valid scalar')
  assert(sodium.sodium_is_zero(x, x.byteLength) === false, 'x must be valid scalar')

  sodium.crypto_scalarmult_ed25519_base(xG, x)
  assert(sodium.crypto_core_ed25519_is_valid_point(xG))
  sodium.crypto_scalarmult_ed25519(rH, r, H)
  assert(sodium.crypto_core_ed25519_is_valid_point(rH))

  sodium.crypto_core_ed25519_add(c, xG, rH)
  sodium.sodium_memzero(xG)
  sodium.sodium_memzero(rH)
  assert(sodium.crypto_core_ed25519_is_valid_point(c))

  var res = sodium.sodium_memcmp(commitment, c, commitment.byteLength)
  sodium.sodium_memzero(c)
  return res
}

function addDecommitments (out, r1, r2) {
  assert(out.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(r1.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(r2.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)

  sodium.sodium_add(out, r1)
  sodium.sodium_add(out, r2)
}

function addCommitments (out, c1, c2) {
  assert(out.byteLength === sodium.crypto_core_ed25519_BYTES)
  assert(c1.byteLength === sodium.crypto_core_ed25519_BYTES)
  assert(c2.byteLength === sodium.crypto_core_ed25519_BYTES)
  assert(sodium.crypto_core_ed25519_is_valid_point(c1), 'c1 must be valid point')
  assert(sodium.crypto_core_ed25519_is_valid_point(c2), 'c2 must be valid point')

  sodium.crypto_core_ed25519_add(out, c1, c2)
  assert(sodium.crypto_core_ed25519_is_valid_point(out))
}
