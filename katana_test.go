package katana

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"io"
	"os"
	"testing"

	. "github.com/essentialkaos/check"
)

// ////////////////////////////////////////////////////////////////////////////////// //

func Test(t *testing.T) { TestingT(t) }

type KatanaSuite struct{}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = Suite(&KatanaSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *KatanaSuite) TestSecretBuildErrors(c *C) {
	c.Assert(Add(""), Equals, ErrEmptySecretData)
	c.Assert(AddHex(""), Equals, ErrEmptySecretData)
	c.Assert(AddHex("~~~~").Error(), Equals, `Can't decode hex-encoded secret data: encoding/hex: invalid byte: U+007E '~'`)
	c.Assert(AddBase64(""), Equals, ErrEmptySecretData)
	c.Assert(AddBase64("~~~~").Error(), Equals, `Can't decode base64-encoded secret data: illegal base64 data at input byte 0`)
	c.Assert(AddEnv(""), Equals, ErrEmptyEnvVarName)
	c.Assert(AddEnv("__UNKNOWN__"), Equals, ErrEmptyEnvVar)
	c.Assert(AddFile(""), Equals, ErrEmptySecretPath)
	c.Assert(AddFile("/__unknown__"), NotNil)
}

func (s *KatanaSuite) TestFileErrors(c *C) {
	var f *File

	c.Assert(f.Name(), Equals, "")
	c.Assert(f.Chmod(0644), Equals, ErrNilFile)
	c.Assert(f.Chown(0, 0), Equals, ErrNilFile)
	c.Assert(f.Close(), Equals, ErrNilFile)
	c.Assert(f.String(), Equals, "&katana.File{nil}")

	_, err := f.Stat()
	c.Assert(err, Equals, ErrNilFile)

	_, err = f.Write(nil)
	c.Assert(err, Equals, ErrNilFile)

	_, err = f.Read(nil)
	c.Assert(err, Equals, ErrNilFile)
}

func (s *KatanaSuite) TestSecretBuild(c *C) {
	secret = nil

	os.Setenv("TEST_KATANA_KEY", "[ENV]")

	tempFile := c.MkDir() + "/file.tmp"
	err := os.WriteFile(tempFile, []byte("TESTdata1234"), 0644)

	c.Assert(err, IsNil)

	c.Assert(Add("[STATIC]"), IsNil)
	c.Assert(AddHex("5b4845585d"), IsNil)
	c.Assert(AddBase64("W0JBU0Vd"), IsNil)
	c.Assert(AddEnv("TEST_KATANA_KEY"), IsNil)
	c.Assert(AddFile(tempFile), IsNil)

	secret = nil
}

func (s *KatanaSuite) TestBasic(c *C) {
	_, err := OpenFile("/test", os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, Equals, ErrEmptySecret)
	_, err = Open("/test")
	c.Assert(err, Equals, ErrEmptySecret)

	c.Assert(Add("[STATIC]"), IsNil)

	_, err = OpenFile("/test", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	c.Assert(err, Equals, ErrAppendNotSupported)

	_, err = OpenFile("/test", os.O_CREATE|os.O_RDONLY, 0)
	c.Assert(err, ErrorMatches, "Can't open file: open /test: permission denied")
	_, err = Open("/test")
	c.Assert(err, ErrorMatches, "Can't open file: open /test: no such file or directory")

	tmpFile := c.MkDir() + "/file.txt"

	f, err := OpenFile(tmpFile, os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	c.Assert(f.Name(), Equals, tmpFile)
	c.Assert(f.String(), Not(Equals), "")
	_, err = f.Stat()
	c.Assert(err, IsNil)
	c.Assert(f.Chmod(0644), IsNil)
	c.Assert(f.Chown(-1, os.Getgid()), IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = OpenFile(tmpFile, os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	_, err = f.Write([]byte("TEST-DATA-1234"))
	c.Assert(err, IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = OpenFile(tmpFile, os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	data, err := io.ReadAll(f)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234")
	c.Assert(f.Close(), IsNil)

	f, err = Open(tmpFile)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	data, err = io.ReadAll(f)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234")
	c.Assert(f.Close(), IsNil)
}
