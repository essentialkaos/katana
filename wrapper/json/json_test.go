package json

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"math"
	"testing"

	"github.com/essentialkaos/katana"

	. "github.com/essentialkaos/check"
)

// ////////////////////////////////////////////////////////////////////////////////// //

func Test(t *testing.T) { TestingT(t) }

type JSONSuite struct{}

type Example struct {
	Str  string
	Num  int64
	Bool bool
}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = Suite(&JSONSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *JSONSuite) TestBasic(c *C) {
	w := Wrap(katana.NewSecret("Test1234"))
	dataIn := &Example{"Test", 1234, true}

	encDate, err := w.Encrypt(dataIn)
	c.Assert(err, IsNil)
	c.Assert(encDate, Not(HasLen), 0)

	dataOut := &Example{}
	err = w.Decrypt(encDate, dataOut)
	c.Assert(err, IsNil)
	c.Assert(dataOut, DeepEquals, dataIn)
}

func (s *JSONSuite) TestErrors(c *C) {
	var w *Wrapper

	dataIn := &Example{"Test", 1234, true}
	dataOut := &Example{}

	_, err := w.Encrypt(dataIn)
	c.Assert(err, Equals, ErrNilWrapper)
	err = w.Decrypt([]byte(`TEST`), dataOut)
	c.Assert(err, Equals, ErrNilWrapper)

	w = &Wrapper{}

	_, err = w.Encrypt("test")
	c.Assert(err, Equals, ErrNoSecret)
	err = w.Decrypt([]byte(`TEST`), dataOut)
	c.Assert(err, Equals, ErrNoSecret)

	w = Wrap(katana.NewSecret("Test1234"))

	_, err = w.Encrypt(nil)
	c.Assert(err, NotNil)
	_, err = w.Encrypt(map[string]float64{"test": math.NaN()})
	c.Assert(err, NotNil)
	err = w.Decrypt(nil, dataOut)
	c.Assert(err, Equals, ErrEmptyData)

	err = w.Decrypt([]byte(`TEST`), nil)
	c.Assert(err, NotNil)
	err = w.Decrypt([]byte(`TEST`), dataOut)
	c.Assert(err, NotNil)
}
