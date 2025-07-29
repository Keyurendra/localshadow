package artifact

import "io"

type Findings interface {
	JSON() []byte
	JSONReader() io.Reader
	DataType() string
}
