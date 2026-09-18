// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import (
	"errors"
	"net"
	"testing"
)

func TestReadPacketRejectsOversizedBodyFromHeader(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	mc := &mysqlConn{
		buf:               newBuffer(),
		netConn:           client,
		rawConn:           client,
		cfg:               NewConfig(),
		closech:           make(chan struct{}),
		maxReadPacketSize: 32,
	}

	written := make(chan error, 1)
	go func() {
		// The declared 4096-byte body is deliberately never sent. A bounded
		// reader must reject it from this header instead of waiting for data.
		_, err := server.Write([]byte{0x00, 0x10, 0x00, 0x00})
		written <- err
	}()

	_, err := mc.readPacket()
	if !errors.Is(err, ErrReadPktTooLarge) {
		t.Fatalf("readPacket() error = %v, want ErrReadPktTooLarge", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("write packet header: %v", err)
	}
}
