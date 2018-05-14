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
  nums,
  commit,
  open,
  accumulateCommitments,
  accumulateDecommitments,

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
  sodium.sodium_memzero(rnd)
}

function nums (out, input) {
  assert(out.byteLength === PARAM_BYTES, 'out must be PARAM_BYTES long')
  assert(out.byteLength, 'input must be Buffer or TypedArray')

  sodium.crypto_generichash(rnd, input)
  sodium.crypto_core_ed25519_from_uniform(out, rnd)
  sodium.sodium_memzero(rnd)
}

var xG = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_BYTES)
var rH = sodium.sodium_malloc(sodium.crypto_scalarmult_ed25519_BYTES)
function commit (commitment, r, x, H, useR) {
  assert(commitment.byteLength === COMMITMENT_BYTES, 'commitment must be COMMITMENT_BYTES long')
  assert(r.byteLength === RBYTES, 'r must be RBYTES long')
  assert(x.byteLength === DATA_BYTES, 'x must be DATA_BYTES long')
  assert(H.byteLength === PARAM_BYTES, 'H must be PARAM_BYTES long')
  assert(sodium.crypto_core_ed25519_is_valid_point(H), 'H must be valid point')

  sodium.crypto_scalarmult_ed25519_base(xG, x)
  if (useR !== true) {
    sodium.randombytes_buf(r)
    r[31] &= 0b00001111
  }
  sodium.crypto_scalarmult_ed25519(rH, r, H)
  sodium.crypto_core_ed25519_add(commitment, xG, rH)
  sodium.sodium_memzero(xG)
  sodium.sodium_memzero(rH)
}

var c = sodium.sodium_malloc(sodium.crypto_core_ed25519_BYTES)
function open (commitment, r, x, H) {
  // defer all other assertions to `commit`
  assert(sodium.crypto_core_ed25519_is_valid_point(commitment), 'commitment must be valid point')

  commit(c, r, x, H, true)

  var res = sodium.sodium_memcmp(commitment, c, commitment.byteLength)
  sodium.sodium_memzero(c)
  return res
}

function accumulateDecommitments (acc, r) {
  assert(acc.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  assert(r.byteLength === sodium.crypto_scalarmult_ed25519_SCALARBYTES)

  var nlz1 = Math.clz32(acc[31] << 24)
  var nlz2 = Math.clz32(r[31] << 24)

  // since clz(ORDER) is 3, we know that nlz > 4 can at most be ~ ORDER / 2
  if (nlz1 > 4 && nlz2 > 4) {
    sodium.sodium_add(acc, r)
    return
  }

  // if msb of out and r is 0, then we can safely add them without overflow
  var willNotOverflow1 = nlz1 > 0 && nlz2 > 0
  // otherwise if msb of either is 1, then nlz of the other must be at least 2
  // to prevent overflow (triangle inequality)
  var willNotOverflow2 = nlz1 > 1 || nlz2 > 1

  // and then decode
  if (willNotOverflow1 || willNotOverflow2) {
    sodium.sodium_add(acc, r)
    codec.encode(codec.decode(acc, 0, 32) % ORDER, acc)
    acc.fill(0, codec.encode.bytes)
    return
  }

  // otherwise we need to do a full decoding
  var n1 = codec.decode(acc)
  var n2 = codec.decode(r)
  var nacc = (n1 + n2) % ORDER
  codec.encode(nacc, acc)
  acc.fill(0, codec.encode.bytes)
}

function accumulateCommitments (acc, c) {
  assert(acc.byteLength === sodium.crypto_core_ed25519_BYTES)
  assert(c.byteLength === sodium.crypto_core_ed25519_BYTES)
  assert(sodium.crypto_core_ed25519_is_valid_point(acc), 'acc must be valid point')
  assert(sodium.crypto_core_ed25519_is_valid_point(c), 'c must be valid point')

  sodium.crypto_core_ed25519_add(acc, acc, c)
}
