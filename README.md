# `pedersen-commitments`

>

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

### `pedersen.addCommitments(sum, a, b)`

### `pedersen.addDecommitments(sum, a, b)`

## Install

```sh
npm install pedersen-commitments
```

## License

[ISC](LICENSE)
