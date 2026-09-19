package queryservice

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
)

const requestedProfileHashDomain = "quordon/requested-profile/v1\x00"
const requestedDatasourceHashDomain = "quordon/requested-datasource/v1\x00"

func auditIdentifierHash(domain, identifier string) string {
	writer := hashStringWriter{destination: sha256.New()}
	_, _ = io.WriteString(&writer, domain)
	_, _ = io.WriteString(&writer, identifier)
	return hex.EncodeToString(writer.destination.Sum(nil))
}

// hashStringWriter keeps io.WriteString from materializing the complete input
// as []byte when the destination hash does not implement io.StringWriter.
type hashStringWriter struct {
	destination hash.Hash
	buffer      [sha256.BlockSize]byte
}

func (w *hashStringWriter) Write(value []byte) (int, error) {
	return w.destination.Write(value)
}

func (w *hashStringWriter) WriteString(value string) (int, error) {
	written := 0
	for len(value) != 0 {
		chunkBytes := min(len(value), len(w.buffer))
		copy(w.buffer[:chunkBytes], value[:chunkBytes])
		count, err := w.destination.Write(w.buffer[:chunkBytes])
		written += count
		if err != nil {
			return written, err
		}
		if count != chunkBytes {
			return written, io.ErrShortWrite
		}
		value = value[chunkBytes:]
	}
	return written, nil
}
