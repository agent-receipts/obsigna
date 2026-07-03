package did

import (
	"fmt"
	"math/big"
)

// base58btcAlphabet is the Bitcoin base58 alphabet: 0, O, I, and l are
// excluded to avoid visual ambiguity, per ADR-0007's resolution algorithm.
const base58btcAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58btcIndex = func() [256]int8 {
	var idx [256]int8
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(base58btcAlphabet); i++ {
		idx[base58btcAlphabet[i]] = int8(i)
	}
	return idx
}()

// base58btcEncode encodes data using the base58btc alphabet. Each leading
// zero byte in data becomes a leading '1' in the output, matching the
// standard base58 convention.
func base58btcEncode(data []byte) string {
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}

	n := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	mod := new(big.Int)

	out := make([]byte, 0, len(data)*138/100+1)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base58btcAlphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base58btcAlphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// base58btcDecode decodes a base58btc string to bytes. It rejects any
// character outside the base58btc alphabet, including the visually
// ambiguous characters 0, O, I, and l that base58btc deliberately excludes.
func base58btcDecode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == base58btcAlphabet[0] {
		zeros++
	}

	n := new(big.Int)
	base := big.NewInt(58)
	digit := new(big.Int)
	for i := 0; i < len(s); i++ {
		v := base58btcIndex[s[i]]
		if v < 0 {
			return nil, fmt.Errorf("invalid base58btc character %q at position %d", s[i], i)
		}
		digit.SetInt64(int64(v))
		n.Mul(n, base)
		n.Add(n, digit)
	}

	decoded := n.Bytes()
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}
