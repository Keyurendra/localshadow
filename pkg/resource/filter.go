package resource

import (
	"fmt"
	"regexp"
)

// Filter must be accepted as an argument by every provider's instantiator.
type Filter struct {
	// Name is a regular expression.
	Name string
	// Labels is a set of key-value pairs. Referred to as tags in AWS and
	// metadata in GCP. Both key & value must be a regular expression or an
	// empty string.
	Labels map[string]string
}

type PrecompiledFilter struct {
	Name   *regexp.Regexp
	Labels []PrecompiledLabelFilter
}

type PrecompiledLabelFilter struct {
	Key   *regexp.Regexp
	Value *regexp.Regexp
}

func (rf Filter) Precompile() (*PrecompiledFilter, error) {
	var name *regexp.Regexp = nil
	if rf.Name != "" {
		n, err := regexp.Compile(rf.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid name regex %q: %w", rf.Name, err)
		}
		name = n
	}

	var labels []PrecompiledLabelFilter
	for k, v := range rf.Labels {
		if k == "" && v == "" {
			continue
		}
		keyReg, err := regexp.Compile(k)
		if err != nil {
			return nil, fmt.Errorf("invalid label key regex %q: %w", k, err)
		}
		valReg, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("invalid label value regex %q: %w", v, err)
		}
		labels = append(labels, PrecompiledLabelFilter{
			Key:   keyReg,
			Value: valReg,
		})
	}

	return &PrecompiledFilter{
		Name:   name,
		Labels: labels,
	}, nil
}
