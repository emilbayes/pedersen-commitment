var pedersen = require('.')
var test = require('tape')
var codec = require('biguintle')
var unif = require('secure-random-uniform/bigint')
var sodium = require('sodium-native')

test('simple', function (assert) {
  var H = Buffer.alloc(pedersen.PARAM_BYTES)
  pedersen.init(H)

  var a = unif(2n ** 256n)
  var ab = codec.encode(a, Buffer.alloc(pedersen.DATA_BYTES))
  var b = unif(2n ** 256n)
  var bb = codec.encode(b, Buffer.alloc(pedersen.DATA_BYTES))

  var ca = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var ra = Buffer.alloc(pedersen.RBYTES)
  var cb = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var rb = Buffer.alloc(pedersen.RBYTES)

  pedersen.commit(ca, ra, ab, H)
  pedersen.commit(cb, rb, bb, H)

  assert.ok(pedersen.open(ca, ra, ab, H))
  assert.ok(pedersen.open(cb, rb, bb, H))

  var sum = BigInt.asUintN(pedersen.DATA_BYTES * 8, a + b)
  var sumb = codec.encode(sum, Buffer.alloc(pedersen.DATA_BYTES))
  pedersen.addDecommitments(sumb, ab, bb)
  var sumr = Buffer.alloc(pedersen.RBYTES)
  var sumc = Buffer.alloc(pedersen.COMMITMENT_BYTES)

  pedersen.addCommitments(sumc, ca, cb)
  pedersen.addDecommitments(sumr, ra, rb)

  var cc = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var rc = Buffer.alloc(pedersen.RBYTES)

  pedersen.commit(cc, rc, sumb, H, sumr)

  assert.ok(pedersen.open(cc, rc, sumb, H))
  assert.ok(pedersen.open(sumc, sumr, sumb, H))

  assert.end()
})

test('sum', function (assert) {
  var rnds = Array.from({length: 10}, _ => unif(2n ** 256n))

  var sum = codec.encode(BigInt.asUintN(pedersen.DATA_BYTES * 8, rnds.reduce((s, e) => s + e, 0n)), Buffer.alloc(pedersen.DATA_BYTES))

  var xs = rnds.map(n => codec.encode(n, Buffer.alloc(pedersen.DATA_BYTES)))
  console.log(xs)

  var H = Buffer.alloc(pedersen.PARAM_BYTES)
  pedersen.init(H)

  var cs = rnds.map(_ => Buffer.alloc(pedersen.COMMITMENT_BYTES))
  var keys = rnds.map(_ => Buffer.alloc(pedersen.RBYTES))
  cs.forEach((c, i) => pedersen.commit(c, keys[i], xs[i], H))

  var sumcs = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var sumrs = Buffer.alloc(pedersen.RBYTES)

  for (var i = 0; i < cs.length; i += 2) {
    pedersen.addCommitments(sumcs, cs[i], cs[i + 1])
    pedersen.addDecommitments(sumrs, keys[i], keys[i + 1])
  }

  assert.ok(pedersen.open(sumcs, sumrs, sum, H))
  assert.end()
})
