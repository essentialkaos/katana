package katana

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"
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

func (s *KatanaSuite) TestSecretBuild(c *C) {
	os.Setenv("KATANA_TEST_KEY", "[ENV]")

	tempFile := c.MkDir() + "/file.tmp"
	err := os.WriteFile(tempFile, []byte("TESTdata1234"), 0644)
	c.Assert(err, IsNil)

	sk := NewSecret("ABCD")
	c.Assert(sk, NotNil)
	c.Assert(sk.Validate(), IsNil)
	c.Assert(sk.pwd.Data, DeepEquals, []byte("ABCD"))

	sk.Add("[STATIC]")
	sk.AddHex("5b4845585d")
	sk.AddBase64("W0JBU0Vd")
	sk.AddEnv("KATANA_TEST_KEY")
	sk.AddFile(tempFile)

	c.Assert(sk.Validate(), IsNil)
}

func (s *KatanaSuite) TestSecretErrors(c *C) {
	var skn *Secret

	c.Assert(NewSecret("").Validate(), Equals, ErrEmptySecretData)

	ske := &Secret{err: fmt.Errorf("TEST-ERROR")}

	c.Assert(NewSecret("!").Add("").Validate(), Equals, ErrEmptySecretData)
	c.Assert(skn.Add("test").Validate(), Equals, ErrNilSecret)
	c.Assert(ske.Add("test").Validate().Error(), Equals, "TEST-ERROR")

	c.Assert(NewSecret("!").AddHex("").Validate(), Equals, ErrEmptySecretData)
	c.Assert(skn.AddHex("test").Validate(), Equals, ErrNilSecret)
	c.Assert(ske.AddHex("test").Validate().Error(), Equals, "TEST-ERROR")
	c.Assert(NewSecret("!").AddHex("%!$%").Validate().Error(), Equals, "encoding/hex: invalid byte: U+0025 '%'")

	c.Assert(NewSecret("!").AddBase64("").Validate(), Equals, ErrEmptySecretData)
	c.Assert(skn.AddBase64("test").Validate(), Equals, ErrNilSecret)
	c.Assert(ske.AddBase64("test").Validate().Error(), Equals, "TEST-ERROR")
	c.Assert(NewSecret("!").AddBase64("%!$%").Validate().Error(), Equals, "illegal base64 data at input byte 0")

	c.Assert(NewSecret("!").AddEnv("").Validate(), Equals, ErrEmptyEnvVarName)
	c.Assert(NewSecret("!").AddEnv("test").Validate(), Equals, ErrEmptyEnvVar)
	c.Assert(skn.AddEnv("test").Validate(), Equals, ErrNilSecret)
	c.Assert(ske.AddEnv("test").Validate().Error(), Equals, "TEST-ERROR")

	c.Assert(NewSecret("!").AddFile("").Validate(), Equals, ErrEmptySecretPath)
	c.Assert(skn.AddFile("test").Validate(), Equals, ErrNilSecret)
	c.Assert(ske.AddFile("test").Validate().Error(), Equals, "TEST-ERROR")
	c.Assert(NewSecret("!").AddFile("test").Validate().Error(), Equals, "Can't open file \"test\": open test: no such file or directory")

	c.Assert(skn.Validate(), Equals, ErrNilSecret)

	skm := &Secret{}
	c.Assert(skm.Validate(), Equals, ErrEmptySecretData)
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

func (s *KatanaSuite) TestHelpersErrors(c *C) {
	var skn *Secret

	_, err := skn.ReadFile("/test")
	c.Assert(err, NotNil)

	err = skn.WriteFile("/test", nil, 0644)
	c.Assert(err, NotNil)
}

func (s *KatanaSuite) TestBasic(c *C) {
	var skn *Secret

	_, err := skn.OpenFile("/test", os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, Equals, ErrNilSecret)
	_, err = skn.Open("/test")
	c.Assert(err, Equals, ErrNilSecret)

	sk := NewSecret("TEST")
	c.Assert(sk.Validate(), IsNil)

	_, err = sk.OpenFile("/test", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	c.Assert(err, Equals, ErrAppendNotSupported)

	tmpFile := c.MkDir() + "/file.txt"

	f, err := sk.OpenFile(tmpFile, os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	c.Assert(f.Name(), Equals, tmpFile)
	c.Assert(f.String(), Not(Equals), "")
	_, err = f.Stat()
	c.Assert(err, IsNil)
	c.Assert(f.Chmod(0644), IsNil)
	c.Assert(f.Chown(-1, os.Getgid()), IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = sk.OpenFile(tmpFile, os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	_, err = f.Write([]byte("TEST-DATA-1234"))
	c.Assert(err, IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = sk.OpenFile(tmpFile, os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	data, err := io.ReadAll(f)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234")
	c.Assert(f.Close(), IsNil)

	f, err = sk.Open(tmpFile)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	data, err = io.ReadAll(f)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234")
	c.Assert(f.Close(), IsNil)

	tmpFile2 := c.MkDir() + "/file2.txt"

	err = sk.WriteFile(tmpFile2, []byte("TEST-DATA-1234-2"), 0644)
	c.Assert(err, IsNil)

	data, err = sk.ReadFile(tmpFile2)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234-2")
}
