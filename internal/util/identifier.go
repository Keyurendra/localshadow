package util

import (
	"fmt"
	"time"
)

const isosecLayout = "20060102150405"

func NewIsoSecIdentifier() string {
	return time.Now().UTC().Format(isosecLayout)
}

func NewIsoNanoSecIdentifier() string {
	t := time.Now().UTC()
	return fmt.Sprintf("%s%s", t.Format(isosecLayout), t.Format(".999999999")[1:])
}
