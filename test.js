var pedersen = require('.')
var test = require('tape')
var codec = require('biguintle')
var unif = require('secure-random-uniform/bigint')
var sodium = require('sodium-native')

test('simple', function (assert) {
  var H = Buffer.alloc(pedersen.PARAM_BYTES)
  pedersen.init(H)
  var a = unif(pedersen.ORDER)
  var ab = codec.encode(a, Buffer.alloc(pedersen.DATA_BYTES))
  var b = unif(pedersen.ORDER)
  var bb = codec.encode(b, Buffer.alloc(pedersen.DATA_BYTES))

  var ca = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var ra = Buffer.alloc(pedersen.RBYTES)
  var cb = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var rb = Buffer.alloc(pedersen.RBYTES)

  pedersen.commit(ca, ra, ab, H)
  pedersen.commit(cb, rb, bb, H)

  assert.ok(pedersen.open(ca, ra, ab, H))
  assert.ok(pedersen.open(cb, rb, bb, H))

  var sumb = codec.encode((a + b) % pedersen.ORDER, Buffer.alloc(pedersen.DATA_BYTES))
  var sumr = Buffer.alloc(pedersen.RBYTES)
  var sumc = Buffer.alloc(pedersen.COMMITMENT_BYTES)

  sumc.set(ca)
  pedersen.accumulateCommitments(sumc, cb)
  sumr.set(ra)
  pedersen.accumulateDecommitments(sumr, rb)

  var cc = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var rc = Buffer.alloc(pedersen.RBYTES)

  pedersen.commit(cc, rc, sumb, H, sumr)

  assert.ok(pedersen.open(cc, rc, sumb, H))
  assert.ok(pedersen.open(sumc, sumr, sumb, H))

  assert.end()
})

test('sum', function (assert) {
  var H = Buffer.alloc(pedersen.PARAM_BYTES)
  pedersen.init(H)

  // we can maximum contain a sum of ~ 2^252 due to the order of the group, so we
  // must make sure that the total sum is below this
  var len = 10000
  var MAX = pedersen.ORDER / BigInt(len) // - 2n ** BigInt(Math.ceil(Math.log2(len)))
  var rnds = Array.from({length: len}, _ => unif(MAX))

  var xs = rnds.map(n => codec.encode(n, Buffer.alloc(pedersen.DATA_BYTES)))

  // assert.same(rnds, xs.map(n => codec.decode(n)))

  var cs = rnds.map(_ => Buffer.alloc(pedersen.COMMITMENT_BYTES))
  var keys = rnds.map(_ => Buffer.alloc(pedersen.RBYTES))
  console.time('commit')
  cs.forEach((c, i) => pedersen.commit(c, keys[i], xs[i], H))
  console.timeEnd('commit')

  // assert.ok(cs.map((c, i) => pedersen.open(c, keys[i], xs[i], H)).every(Boolean))

  var sumcs = Buffer.alloc(pedersen.COMMITMENT_BYTES)
  var sumrs = Buffer.alloc(pedersen.RBYTES)

  console.time('add')
  sumcs.set(cs[0])
  sumrs.set(keys[0])
  var sum = rnds[0]
  var sumb = Buffer.alloc(pedersen.DATA_BYTES)
  for (var i = 1; i < cs.length; i++) {
    pedersen.accumulateCommitments(sumcs, cs[i])
    pedersen.accumulateDecommitments(sumrs, keys[i])
    sum = (sum + rnds[i]) % pedersen.ORDER
    codec.encode(sum, sumb, 0)
    sumb.fill(0, codec.encode.bytes)
    if (codec.decode(sumb) !== sum) assert.fail(sum)

    if(pedersen.open(sumcs, sumrs, sumb, H) === false) {
      assert.fail('Failed to open commitment at iteration ' + i)
      break
    }
  }
  console.timeEnd('add')

  assert.end()
})
