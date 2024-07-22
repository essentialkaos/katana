package katana

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"bytes"
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

	skrt := NewSecret("ABCD")
	c.Assert(skrt, NotNil)
	c.Assert(skrt.Validate(), IsNil)
	c.Assert(skrt.pwd, DeepEquals, []byte("ABCD"))

	skrt.Add("[STATIC]")
	skrt.AddHex("5b4845585d")
	skrt.AddBase64("W0JBU0Vd")
	skrt.AddEnv("KATANA_TEST_KEY")
	skrt.AddFile(tempFile)

	c.Assert(skrt.Validate(), IsNil)
	c.Assert(skrt.Checksum(), HasLen, 32)
	c.Assert(skrt.Checksum().String(), Equals, "9dc7364c4a6938d21dfe9ba4755355d7a29620ddcce9dbbdc932027f642bc601")
	c.Assert(skrt.Checksum().Short(), Equals, "9dc7364")
	c.Assert(skrt.String(), Equals, "katana.Secret{9dc7364}")
}

func (s *KatanaSuite) TestSecretErrors(c *C) {
	var skrt *Secret

	c.Assert(NewSecret("").Validate(), Equals, ErrEmptySecretData)

	skrt2 := &Secret{err: fmt.Errorf("TEST-ERROR")}

	c.Assert(NewSecret("!").Add("").Validate(), Equals, ErrEmptySecretData)
	c.Assert(skrt.Add("test").Validate(), Equals, ErrNilSecret)
	c.Assert(skrt2.Add("test").Validate().Error(), Equals, "TEST-ERROR")

	c.Assert(NewSecret("!").AddHex("").Validate(), Equals, ErrEmptySecretData)
	c.Assert(skrt.AddHex("test").Validate(), Equals, ErrNilSecret)
	c.Assert(skrt2.AddHex("test").Validate().Error(), Equals, "TEST-ERROR")
	c.Assert(NewSecret("!").AddHex("%!$%").Validate().Error(), Equals, "encoding/hex: invalid byte: U+0025 '%'")

	c.Assert(NewSecret("!").AddBase64("").Validate(), Equals, ErrEmptySecretData)
	c.Assert(skrt.AddBase64("test").Validate(), Equals, ErrNilSecret)
	c.Assert(skrt2.AddBase64("test").Validate().Error(), Equals, "TEST-ERROR")
	c.Assert(NewSecret("!").AddBase64("%!$%").Validate().Error(), Equals, "illegal base64 data at input byte 0")

	c.Assert(NewSecret("!").AddEnv("").Validate(), Equals, ErrEmptyEnvVarName)
	c.Assert(NewSecret("!").AddEnv("test").Validate(), Equals, ErrEmptyEnvVar)
	c.Assert(skrt.AddEnv("test").Validate(), Equals, ErrNilSecret)
	c.Assert(skrt2.AddEnv("test").Validate().Error(), Equals, "TEST-ERROR")

	c.Assert(NewSecret("!").AddFile("").Validate(), Equals, ErrEmptySecretPath)
	c.Assert(skrt.AddFile("test").Validate(), Equals, ErrNilSecret)
	c.Assert(skrt2.AddFile("test").Validate().Error(), Equals, "TEST-ERROR")
	c.Assert(NewSecret("!").AddFile("test").Validate().Error(), Equals, "Can't open file \"test\": open test: no such file or directory")

	c.Assert(skrt.Validate(), Equals, ErrNilSecret)

	_, err := skrt.NewReader(nil, MODE_DECRYPT)
	c.Assert(err, Equals, ErrNilSecret)

	_, err = skrt.NewWriter(nil)
	c.Assert(err, Equals, ErrNilSecret)

	_, err = skrt.Encrypt(nil)
	c.Assert(err, Equals, ErrNilSecret)

	_, err = skrt.Decrypt(nil)
	c.Assert(err, Equals, ErrNilSecret)

	c.Assert(skrt.Checksum(), IsNil)
	c.Assert(skrt.Checksum().String(), Equals, "")
	c.Assert(skrt.Checksum().Short(), Equals, "")

	skrt3 := &Secret{}
	c.Assert(skrt3.Validate(), Equals, ErrEmptySecretData)
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
	var skrt *Secret

	_, err := skrt.ReadFile("/test")
	c.Assert(err, NotNil)

	err = skrt.WriteFile("/test", nil, 0644)
	c.Assert(err, NotNil)
}

func (s *KatanaSuite) TestFile(c *C) {
	var skrt *Secret

	_, err := skrt.OpenFile("/test", os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err, Equals, ErrNilSecret)
	_, err = skrt.Open("/test")
	c.Assert(err, Equals, ErrNilSecret)

	skrt = NewSecret("TEST")
	c.Assert(skrt.Validate(), IsNil)

	_, err = skrt.OpenFile("/test", os.O_CREATE|os.O_APPEND, 0644)
	c.Assert(err.Error(), Equals, `Can't open file "/test": Unsupported flag O_APPEND`)
	_, err = skrt.OpenFile("/test", os.O_CREATE|os.O_RDWR, 0644)
	c.Assert(err.Error(), Equals, `Can't open file "/test": Unsupported flag O_RDWR`)

	_, err = skrt.Open("/test")
	c.Assert(err, NotNil)
	_, err = skrt.OpenFile("/test", os.O_CREATE|os.O_RDONLY, 0644)
	c.Assert(err, NotNil)

	tmpFile := c.MkDir() + "/file.txt"

	f, err := skrt.OpenFile(tmpFile, os.O_CREATE|os.O_RDONLY, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	c.Assert(f.Name(), Equals, tmpFile)
	c.Assert(f.String(), Not(Equals), "")
	_, err = f.Stat()
	c.Assert(err, IsNil)
	c.Assert(f.Chmod(0644), IsNil)
	c.Assert(f.Chown(-1, os.Getgid()), IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = skrt.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	_, err = f.Write([]byte("TEST-DATA"))
	c.Assert(err, IsNil)
	_, err = f.Write([]byte("-1234"))
	c.Assert(err, IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = skrt.OpenFile(tmpFile, os.O_CREATE|os.O_RDONLY, 0644)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	_, err = f.Read(make([]byte, 4))
	c.Assert(err, IsNil)
	_, err = f.Read(make([]byte, 4))
	c.Assert(err, IsNil)
	c.Assert(f.Close(), IsNil)

	f, err = skrt.Open(tmpFile)
	c.Assert(err, IsNil)
	c.Assert(f, NotNil)
	data, err := io.ReadAll(f)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234")
	c.Assert(f.Close(), IsNil)

	tmpFile2 := c.MkDir() + "/file2.txt"

	err = skrt.WriteFile(tmpFile2, []byte("TEST-DATA-1234-2"), 0644)
	c.Assert(err, IsNil)

	data, err = skrt.ReadFile(tmpFile2)
	c.Assert(err, IsNil)
	c.Assert(string(data), Equals, "TEST-DATA-1234-2")
}

func (s *KatanaSuite) TestEncryptDecrypt(c *C) {
	skrt := NewSecret("TEST")

	encData, err := skrt.Encrypt([]byte("TEST-DATA-1234"))
	c.Assert(err, IsNil)
	c.Assert(encData, Not(HasLen), 0)

	decData, err := skrt.Decrypt(encData)
	c.Assert(err, IsNil)
	c.Assert(string(decData), Equals, "TEST-DATA-1234")

	_, err = skrt.Decrypt([]byte("1234"))
	c.Assert(err, NotNil)
}

func (s *KatanaSuite) TestReaderWriter(c *C) {
	skrt := NewSecret("TEST")
	tmpFile := c.MkDir() + "/file.txt"

	// WRITER

	fd, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY, 0644)
	c.Assert(err, IsNil)
	c.Assert(fd, NotNil)

	w, err := skrt.NewWriter(fd)
	c.Assert(err, IsNil)
	c.Assert(w.String(), Equals, "katana.Writer{nil}")

	_, err = w.Write([]byte("Test1234"))
	c.Assert(err, IsNil)
	_, err = w.Write([]byte("Test1234"))
	c.Assert(err, IsNil)
	c.Assert(w.String(), Equals, "katana.Writer{ENCRYPT}")

	err = w.Close()
	c.Assert(err, IsNil)

	// READER

	fd, err = os.Open(tmpFile)
	c.Assert(err, IsNil)
	c.Assert(fd, NotNil)

	r, err := skrt.NewReader(fd, MODE_DECRYPT)
	c.Assert(err, IsNil)
	c.Assert(r.String(), Equals, "katana.Reader{nil}")

	_, err = r.Read(make([]byte, 8))
	c.Assert(err, IsNil)
	_, err = r.Read(make([]byte, 8))
	c.Assert(err, IsNil)
	c.Assert(r.String(), Equals, "katana.Reader{DECRYPT}")

	src := bytes.NewReader([]byte("Test1234"))
	r, err = skrt.NewReader(src, MODE_ENCRYPT)
	c.Assert(err, IsNil)
	encData, err := io.ReadAll(r)
	c.Assert(err, IsNil)
	decData, err := skrt.Decrypt(encData)
	c.Assert(err, IsNil)
	c.Assert(string(decData), Equals, "Test1234")

	_, err = skrt.getDecryptReader(bytes.NewReader([]byte("")))
	c.Assert(err, NotNil)
}
