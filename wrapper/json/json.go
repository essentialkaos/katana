package json

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"encoding/json"
	"fmt"

	"github.com/essentialkaos/katana"
	"github.com/essentialkaos/katana/wrapper"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type JSONWrapper struct {
	skrt *katana.Secret
}

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrNilWrapper = fmt.Errorf("Wrapper is nil")
	ErrNoSecret   = fmt.Errorf("No secret")
)

// ////////////////////////////////////////////////////////////////////////////////// //

// validate wrapper interface
var _ wrapper.Wrapper = (*JSONWrapper)(nil)

// ////////////////////////////////////////////////////////////////////////////////// //

// Wrap creates JSON wrapper
func Wrap(skrt *katana.Secret) *JSONWrapper {
	return &JSONWrapper{skrt}
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Encrypt encodes given object and encrypts data
func (w *JSONWrapper) Encrypt(data any) ([]byte, error) {
	switch {
	case w == nil:
		return nil, ErrNilWrapper
	case w.skrt == nil:
		return nil, ErrNoSecret
	}

	raw, err := json.Marshal(data)

	if err != nil {
		return nil, err
	}

	return w.skrt.Encrypt(raw)
}

// Decrypt decrypts given data and decodes it
func (w *JSONWrapper) Decrypt(data []byte, v any) error {
	switch {
	case w == nil:
		return ErrNilWrapper
	case w.skrt == nil:
		return ErrNoSecret
	}

	raw, err := w.skrt.Decrypt(data)

	if err != nil {
		return err
	}

	return json.Unmarshal(raw, v)
}
