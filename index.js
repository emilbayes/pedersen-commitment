var sodium = require('sodium-native')

function init () {
  var a = Buffer.alloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)
  randomScalar(a)

  var h = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  sodium.crypto_scalarmult_ed25519_base(h, a)

  return h
}

function commit (x, h, r) {
  if (!r) {
    r = Buffer.alloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)
    randomScalar(r)
  }

  var xG = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  var rH = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)

  sodium.crypto_scalarmult_ed25519_base(xG, x)
  sodium.crypto_scalarmult_ed25519(rH, r, h)

  var commitment = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_add(commitment, xG, rH)

  return [commitment, r]
}

function open (c, x, r, h) {
  var xG = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  var rH = Buffer.alloc(sodium.crypto_scalarmult_ed25519_BYTES)

  sodium.crypto_scalarmult_ed25519_base(xG, x)
  sodium.crypto_scalarmult_ed25519(rH, r, h)

  var commitment = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_add(commitment, xG, rH)

  return sodium.sodium_memcmp(c, commitment, c.byteLength)
}

function add(c1, c2, r1, r2, h) {
  var rsum = Buffer.from(r1)
  sodium.sodium_add(rsum, r2)

  var csum = Buffer.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_add(csum, c1, c2)
  return [csum, rsum]
}

function randomScalar (s) {
  sodium.randombytes_buf(s.slice(0, 31)) // 248 bits
  s[0] &= 248 // clear lower 3 bits
}

var h = init()
var x = Buffer.alloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)
var y = Buffer.alloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)
var z = Buffer.alloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)

var sum = Buffer.alloc(sodium.crypto_scalarmult_ed25519_SCALARBYTES)

for (var i = 0; i < 1e6; i++) {
  sum.fill(0)
  x.writeUIntLE(sodium.randombytes_uniform(0xffffffff), 6, 6)
  y.writeUIntLE(sodium.randombytes_uniform(0xffffffff), 6, 6)
  z.writeUIntLE(sodium.randombytes_uniform(0xffffffff), 6, 6)

  sodium.sodium_add(sum, x)
  sodium.sodium_add(sum, y)
  sodium.sodium_add(sum, z)

  var [c1, r1] = commit(x, h)
  var [c2, r2] = commit(y, h)
  var [c3, r3] = commit(z, h)

  var [cs1, rs1] = add(c1, c2, r1, r2, h)
  var [cs2, rs2] = add(cs1, c3, rs1, r3, h)

  if (open(c1, x, r1, h) === false) process.exit(1)
  if (open(c2, y, r2, h) === false) process.exit(2)
  if (open(c3, z, r3, h) === false) process.exit(3)
  if (open(cs2, sum, rs2, h) === false) process.exit(4)
}
