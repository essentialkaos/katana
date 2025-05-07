package katana

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2025 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"

	"github.com/essentialkaos/sio"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// SALT_SIZE is default salt size
const SALT_SIZE = 32

const (
	MODE_ENCRYPT Mode = 0 // Encryption mode
	MODE_DECRYPT Mode = 1 // Decryption mode
)

// ////////////////////////////////////////////////////////////////////////////////// //

// Mode is reader/writer mode
type Mode uint8

// Secret is katana secret storage
type Secret struct {
	pwd []byte
	err error
}

// Reader is encrypted data reader
type Reader struct {
	secret    *Secret
	rawReader io.Reader
	sioReader io.Reader
	mode      Mode
}

// Reader is encrypted data writer
type Writer struct {
	secret    *Secret
	rawWriter io.WriteCloser
	sioWriter io.WriteCloser
	mode      Mode
}

// File represents encrypted file
type File struct {
	secret *Secret
	fd     *os.File
	r      *Reader
	w      *Writer
}

// Checksum is secret checksum
type Checksum []byte

// ////////////////////////////////////////////////////////////////////////////////// //

type intercepterWriter struct {
	secret *Secret
	salt   []byte
	w      io.WriteCloser
}

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrNilFile         = fmt.Errorf("File is nil")
	ErrNilSecret       = fmt.Errorf("Secret is nil")
	ErrEmptySecret     = fmt.Errorf("Secret is empty")
	ErrEmptySecretData = fmt.Errorf("Secret data is empty")
	ErrEmptySecretPath = fmt.Errorf("Secret path is empty")
	ErrEmptyEnvVarName = fmt.Errorf("Environment variable name is empty")
	ErrEmptyEnvVar     = fmt.Errorf("Environment variable is empty")
)

// ////////////////////////////////////////////////////////////////////////////////// //

// NewSecret creates new katana secret
func NewSecret(data string) *Secret {
	s := &Secret{}
	return s.Add(data)
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Add adds static part of the key
func (s *Secret) Add(data string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case data == "":
		s.err = ErrEmptySecretData
		return s
	}

	s.addKeyData([]byte(data))

	return s
}

// AddHex adds hex-encoded static part of the key
func (s *Secret) AddHex(data string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case data == "":
		s.err = ErrEmptySecretData
		return s
	}

	bytes, err := hex.DecodeString(data)

	if err != nil {
		s.err = err
		return s
	}

	s.addKeyData(bytes)

	return s
}

// AddBase64 adds Base64-encoded static part of the key
func (s *Secret) AddBase64(data string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case data == "":
		s.err = ErrEmptySecretData
		return s
	}

	bytes, err := base64.StdEncoding.DecodeString(data)

	if err != nil {
		s.err = err
		return s
	}

	s.addKeyData(bytes)

	return s
}

// AddEnv adds dynamic part of the key for environment variable
func (s *Secret) AddEnv(name string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case name == "":
		s.err = ErrEmptyEnvVarName
		return s
	case os.Getenv(name) == "":
		s.err = ErrEmptyEnvVar
		return s
	}

	s.addKeyData([]byte(os.Getenv(name)))

	err := os.Setenv(name, "")

	if err != nil {
		s.err = fmt.Errorf("Can't clean secret from environment variable: %w", err)
		return s
	}

	return s
}

// AddFile adds dynamic part of the key based on SHA-512 hash of the file
func (s *Secret) AddFile(file string) *Secret {
	switch {
	case s == nil:
		return &Secret{err: ErrNilSecret}
	case s.err != nil:
		return s
	case file == "":
		s.err = ErrEmptySecretPath
		return s
	}

	fd, err := os.OpenFile(file, os.O_RDONLY, 0)

	if err != nil {
		s.err = fmt.Errorf("Can't open file %q: %w", file, err)
		return s
	}

	hasher := sha512.New()
	_, err = io.Copy(hasher, fd)

	if err != nil {
		s.err = fmt.Errorf("Can't calculate file %q hash: %w", file, err)
		return s
	}

	s.addKeyData(hasher.Sum(nil))

	return s
}

// Validate validates secret
func (s *Secret) Validate() error {
	switch {
	case s == nil:
		return ErrNilSecret
	case s.err != nil:
		return s.err
	case len(s.pwd) == 0:
		return ErrEmptySecretData
	}

	return nil
}

// Checksum returns secret checksum
func (s *Secret) Checksum() Checksum {
	if s == nil || s.pwd == nil || len(s.pwd) == 0 {
		return nil
	}

	hasher := sha512.New512_256()
	hasher.Write(s.pwd)

	return Checksum(hasher.Sum(nil))
}

// String returns string representation of secret
func (s *Secret) String() string {
	return fmt.Sprintf("katana.Secret{%s}", s.Checksum().Short())
}

// ////////////////////////////////////////////////////////////////////////////////// //

// String returns full checksum as string
func (c Checksum) String() string {
	if len(c) != 32 {
		return ""
	}

	return fmt.Sprintf("%064x", []byte(c))
}

// Short returns short checksum (first 7 bytes)
func (c Checksum) Short() string {
	if len(c) != 32 {
		return ""
	}

	return c.String()[:7]
}

// ////////////////////////////////////////////////////////////////////////////////// //

// String returns string representation of mode
func (m Mode) String() string {
	if m == MODE_DECRYPT {
		return "DECRYPT"
	}

	return "ENCRYPT"
}

// ////////////////////////////////////////////////////////////////////////////////// //

// NewReader creates new reader instance
func (s *Secret) NewReader(r io.Reader, mode Mode) (*Reader, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	return &Reader{secret: s, rawReader: r, mode: mode}, nil
}

// NewWriter creates new writer instance
func (s *Secret) NewWriter(w io.WriteCloser) (*Writer, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	return &Writer{secret: s, rawWriter: w, mode: MODE_ENCRYPT}, nil
}

// Encrypt encrypts given data
func (s *Secret) Encrypt(data []byte) ([]byte, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	cfg, salt, err := getSIOConfig(s.pwd, nil)

	if err != nil {
		return nil, fmt.Errorf("Can't create SIO config: %w", err)
	}

	buf := bytes.NewBuffer(salt)
	_, err = sio.Encrypt(buf, bytes.NewReader(data), cfg)

	if err != nil {
		return nil, fmt.Errorf("Can't encrypt data: %w", err)
	}

	return buf.Bytes(), nil
}

// EncryptToBase64 encrypts given data and encodes result to Base64
func (s *Secret) EncryptToBase64(data []byte) ([]byte, error) {
	encData, err := s.Encrypt(data)

	if err != nil {
		return nil, err
	}

	buf := make([]byte, base64.StdEncoding.EncodedLen(len(encData)))
	base64.StdEncoding.Encode(buf, encData)

	return buf, nil
}

// Decrypt decrypts given data
func (s *Secret) Decrypt(data []byte) ([]byte, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	if len(data) < SALT_SIZE {
		return nil, fmt.Errorf("Invalid data size to decrypt")
	}

	salt := data[:SALT_SIZE]
	data = data[SALT_SIZE:]

	cfg, _, err := getSIOConfig(s.pwd, salt)

	if err != nil {
		return nil, fmt.Errorf("Can't create SIO config: %w", err)
	}

	buf := bytes.NewBufferString("")
	_, err = sio.Decrypt(buf, bytes.NewReader(data), cfg)

	if err != nil {
		return nil, fmt.Errorf("Can't decrypt data: %w", err)
	}

	return buf.Bytes(), nil
}

// DecryptFromBase64 decrypts Base64-encoded data
func (s *Secret) DecryptFromBase64(data []byte) ([]byte, error) {
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(buf, data)

	if err != nil {
		return nil, err
	}

	return s.Decrypt(buf[:n])
}

// Open opens the named file for reading. If successful, methods on the returned file
// can be used for reading; the associated file descriptor has mode O_RDONLY.
func (s *Secret) Open(name string) (*File, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	fd, err := os.Open(name)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %w", err)
	}

	return &File{secret: s, fd: fd}, nil
}

// OpenFile opens the named file with specified flag (O_RDONLY etc.). If the file does
// not exist, and the O_CREATE flag is passed, it is created with mode perm (before
// umask).
func (s *Secret) OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	err := s.Validate()

	if err != nil {
		return nil, err
	}

	switch {
	case flag&os.O_APPEND != 0:
		return nil, fmt.Errorf("Can't open file %q: Unsupported flag O_APPEND", name)
	case flag&os.O_RDWR != 0:
		return nil, fmt.Errorf("Can't open file %q: Unsupported flag O_RDWR", name)
	}

	fd, err := os.OpenFile(name, flag, perm)

	if err != nil {
		return nil, fmt.Errorf("Can't open file: %w", err)
	}

	return &File{secret: s, fd: fd}, nil
}

// ReadFile reads the named file and returns the contents
func (s *Secret) ReadFile(name string) ([]byte, error) {
	f, err := s.Open(name)

	if err != nil {
		return nil, err
	}

	defer f.Close()

	return io.ReadAll(f)
}

// WriteFile writes data to the named file, creating it if necessary
func (s *Secret) WriteFile(name string, data []byte, perm os.FileMode) error {
	f, err := s.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)

	if err != nil {
		return err
	}

	defer f.Close()

	_, err = f.Write(data)

	return err
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Read reads and decrypts data
func (r *Reader) Read(p []byte) (int, error) {
	if r.sioReader != nil {
		return r.sioReader.Read(p)
	}

	var err error

	if r.mode == MODE_DECRYPT {
		r.sioReader, err = r.secret.getDecryptReader(r.rawReader)
	} else {
		r.sioReader, err = r.secret.getEncryptReader(r.rawReader)
	}

	if err != nil {
		return 0, fmt.Errorf("Can't create SIO reader: %w", err)
	}

	return r.sioReader.Read(p)
}

// String returns string representation of reader
func (r *Reader) String() string {
	if r == nil || r.sioReader == nil {
		return "katana.Reader{nil}"
	}

	return fmt.Sprintf("katana.Reader{%s}", r.mode)
}

// Write encrypts and writes data
func (w *Writer) Write(p []byte) (int, error) {
	if w.sioWriter != nil {
		return w.sioWriter.Write(p)
	}

	var err error

	w.sioWriter, err = w.secret.getEncryptWriter(w.rawWriter)

	if err != nil {
		return 0, fmt.Errorf("Can't create SIO writer: %w", err)
	}

	return w.sioWriter.Write(p)
}

// Close closes writer
func (w *Writer) Close() error {
	return w.sioWriter.Close()
}

// String returns string representation of writer
func (w *Writer) String() string {
	if w == nil || w.sioWriter == nil {
		return "katana.Writer{nil}"
	}

	return fmt.Sprintf("katana.Writer{%s}", w.mode)
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Write writes len(b) bytes from b to the File
func (f *File) Write(b []byte) (int, error) {
	if f == nil || f.fd == nil {
		return 0, ErrNilFile
	}

	if f.w != nil {
		return f.w.Write(b)
	}

	var err error

	f.w, err = f.secret.NewWriter(f.fd)

	if err != nil {
		return 0, err
	}

	return f.w.Write(b)
}

// Read reads up to len(b) bytes from the File and stores them in b
func (f *File) Read(b []byte) (int, error) {
	if f == nil || f.fd == nil {
		return 0, ErrNilFile
	}

	if f.r != nil {
		return f.r.Read(b)
	}

	var err error

	f.r, err = f.secret.NewReader(f.fd, MODE_DECRYPT)

	if err != nil {
		return 0, err
	}

	return f.r.Read(b)
}

// Close closes the File, rendering it unusable for I/O
func (f *File) Close() error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	var err error

	// Close underlay writer
	if f.w != nil {
		err = f.w.Close()
	} else {
		err = f.fd.Close()
	}

	f.secret = nil

	return err
}

// Name returns the name of the file as presented to Open
func (f *File) Name() string {
	if f == nil || f.fd == nil {
		return ""
	}

	return f.fd.Name()
}

// Stat returns the FileInfo structure describing file
func (f *File) Stat() (os.FileInfo, error) {
	if f == nil || f.fd == nil {
		return nil, ErrNilFile
	}

	return f.fd.Stat()
}

// Chmod changes the mode of the file to mode
func (f *File) Chmod(mode os.FileMode) error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	return f.fd.Chmod(mode)
}

// Chown changes the numeric uid and gid of the named file
func (f *File) Chown(uid, gid int) error {
	if f == nil || f.fd == nil {
		return ErrNilFile
	}

	return f.fd.Chown(uid, gid)
}

// String returns string representation of File
func (f *File) String() string {
	if f == nil || f.fd == nil {
		return "&katana.File{nil}"
	}

	return fmt.Sprintf("&katana.File{%s}", f.fd.Name())
}

// ////////////////////////////////////////////////////////////////////////////////// //

// addKeyData appends key data
func (s *Secret) addKeyData(data []byte) {
	s.pwd = append(s.pwd, data...)

	for i := range data {
		data[i] = 0
	}
}

// getDecryptReader creates decrypt reader (encrypted → raw) instance
func (s *Secret) getDecryptReader(r io.Reader) (io.Reader, error) {
	salt := make([]byte, SALT_SIZE)
	_, err := io.ReadFull(r, salt)

	if err != nil {
		return nil, fmt.Errorf("Can't read salt: %w", err)
	}

	cfg, _, err := getSIOConfig(s.pwd, salt)

	if err != nil {
		return nil, fmt.Errorf("Can't create SIO config: %w", err)
	}

	rr, err := sio.DecryptReader(r, cfg)

	if err != nil {
		return nil, fmt.Errorf("Can't create decrypt reader: %w", err)
	}

	return rr, nil
}

// getEncryptReader creates encrypt reader (raw → encrypted) instance
func (s *Secret) getEncryptReader(r io.Reader) (io.Reader, error) {
	cfg, salt, err := getSIOConfig(s.pwd, nil)

	if err != nil {
		return nil, fmt.Errorf("Can't create SIO config: %w", err)
	}

	rr, err := sio.EncryptReader(r, cfg)

	if err != nil {
		return nil, fmt.Errorf("Can't create decrypt reader: %w", err)
	}

	return io.MultiReader(bytes.NewReader(salt), rr), nil
}

// getEncryptWriter creates encrypt writer (raw → ecnrypted) instance
func (s *Secret) getEncryptWriter(w io.WriteCloser) (io.WriteCloser, error) {
	cfg, salt, err := getSIOConfig(s.pwd, nil)

	if err != nil {
		return nil, fmt.Errorf("Can't create SIO config: %w", err)
	}

	_, err = w.Write(salt)

	if err != nil {
		return nil, fmt.Errorf("Error while writing salt: %w", err)
	}

	ww, err := sio.EncryptWriter(w, cfg)

	if err != nil {
		return nil, fmt.Errorf("Can't create encrypt writer: %w", err)
	}

	return ww, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// getSIOConfig returns configuration for SIO
func getSIOConfig(secret, salt []byte) (sio.Config, []byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, SALT_SIZE)
		io.ReadFull(rand.Reader, salt)
	}

	key, salt, err := deriveKey(secret, salt)

	if err != nil {
		return sio.Config{}, nil, fmt.Errorf("Error while key generation: %w", err)
	}

	return sio.Config{
		Key:          key,
		CipherSuites: []byte{sio.CHACHA20_POLY1305},
	}, salt, nil
}

// deriveKey creates derived key from secret and salt
func deriveKey(key, salt []byte) ([]byte, []byte, error) {
	keyData, err := scrypt.Key(key, salt, 32768, 16, 1, SALT_SIZE)

	if err != nil {
		return nil, salt, err
	}

	return keyData, salt, nil
}
