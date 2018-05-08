var sodium = require('sodium-native')
var assert = require('nanoassert')
var codec = require('biguintle')

var PARAM_BYTES = sodium.crypto_scalarmult_ed25519_BYTES
var COMMITMENT_BYTES = sodium.crypto_scalarmult_ed25519_BYTES
var DATA_BYTES = sodium.crypto_scalarmult_ed25519_SCALARBYTES
var RBYTES = sodium.crypto_scalarmult_ed25519_SCALARBYTES

var ORDER = 2n ** 252n + 27742317777372353535851937790883648493n

module.exports = {
  init,
  commit,
  open,
  addCommitments,
  addDecommitments,

  PARAM_BYTES,
  COMMITMENT_BYTES,
  DATA_BYTES,
  RBYTES,
  ORDER
}

var rnd = sodium.sodium_malloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
function init (out) {
  assert(out.byteLength === PARAM_BYTES, 'out must be PARAM_BYTES long')

  sodium.randombytes_buf(rnd)
  sodium.crypto_core_ed25519_from_uniform(out, rnd)
  assert(sodium.crypto_core_ed25519_is_valid_point(out))
  sodium.sodium_memzero(rnd)
}

var xG = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_BYTES)
var rH = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_BYTES)
function commit (commitment, r, x, H, rr) {
  assert(sodium.sodium_is_zero(x, x.byteLength) === false)
  assert(commitment.byteLength === COMMITMENT_BYTES, 'commitment must be COMMITMENT_BYTES long')
  assert(r.byteLength === RBYTES, 'r must be RBYTES long')
  assert(x.byteLength === DATA_BYTES, 'x must be DATA_BYTES long')
  assert(H.byteLength === PARAM_BYTES, 'H must be PARAM_BYTES long')
  assert(sodium.crypto_core_ed25519_is_valid_point(H))

  sodium.crypto_scalarmult_ed25519_base(xG, x)
  assert(sodium.crypto_core_ed25519_is_valid_point(xG))
  if (!rr) {
    sodium.randombytes_buf(r)
    r[31] = 0b00001111
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
  // assert(sodium.crypto_core_ed25519_is_valid_point(commitment))
  sodium.crypto_scalarmult_ed25519_base(xG, x)
  assert(sodium.crypto_core_ed25519_is_valid_point(xG))
  sodium.crypto_scalarmult_ed25519(rH, r, H)
  assert(sodium.crypto_core_ed25519_is_valid_point(rH))
  // defer all other assertions to `commit`
  assert(sodium.crypto_core_ed25519_is_valid_point(commitment), 'commitment must be a valid point')

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

  var nlz1 = Math.clz32(r1[31] << 24)
  var nlz2 = Math.clz32(r2[31] << 24)

  // since clz(ORDER) is 3, we know that nlz > 4 can at most be ~ ORDER / 2
  if (nlz1 > 4 && nlz2 > 4) {
    sodium.sodium_add(out, r1)
    sodium.sodium_add(out, r2)
    return
  }

  // if msb of r1 and r2 is 0, then we can safely add them without overflow
  var willNotOverflow1 = nlz1 > 0 && nlz2 > 0
  // otherwise if msb of either is 1, then nlz of the other must be at least 2
  // to prevent overflow (triangle inequality)
  var willNotOverflow2 = nlz1 > 1 || nlz2 > 1

  // and then decode
  if (willNotOverflow1 || willNotOverflow2) {
    sodium.sodium_add(out, r1)
    sodium.sodium_add(out, r2)
    codec.encode(codec.decode(out, 0, 32) % ORDER, out)
    out.fill(0, codec.encode.bytes)
    return
  }

  // otherwise we need to do a full decoding
  var n1 = codec.decode(r1)
  var n2 = codec.decode(r2)
  var nout = (n1 + n2) % ORDER
  codec.encode(nout, out)
  out.fill(0, codec.encode.bytes)
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
