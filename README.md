# `pedersen-commitments`

>

Note: This requires a modified libsodium to run without scalar clamping on EC
operations

## Usage

```js
var pedersen = require('pedersen-commitments')

```

## API

### `pedersen.PARAM_BYTES`

### `pedersen.DATA_BYTES`

### `pedersen.COMMITMENT_BYTES`

### `pedersen.RBYTES`

### `pedersen.init(H)`

### `pedersen.commit(commitment, decommitment, value, H)`

### `var bool = pedersen.open(commitment, decommitment, value, H)`

### `pedersen.accumulateCommitments(acc, c)`

### `pedersen.accumulateDecommitments(acc, r)`
Note: this function is **NOT** constant-time.

## Install

```sh
npm install pedersen-commitments
```

## License

[ISC](LICENSE)
