package entropy

import (
	"io"
	"math"
)

const bufSize = 4 * 1024 * 1024 // 4 MB buffer

func Calculate(r io.Reader) (float64, error) {
	var freq [256]uint64
	var total uint64

	buf := make([]byte, bufSize)

	for {
		n, err := r.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}
		if n > 0 {
			total += uint64(n)
			for _, b := range buf[:n] {
				freq[b]++
			}
		}
	}

	// empty file
	if total == 0 {
		return 0, nil
	}

	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(total)
		entropy += -p * math.Log2(p)
	}

	return entropy, nil
}
