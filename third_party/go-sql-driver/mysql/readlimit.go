// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2012 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package mysql

import "context"

type maxReadPacketSizeKey struct{}

// WithMaxReadPacketSize returns a context that limits the size of any logical
// MySQL protocol packet read while executing a query. A non-positive size
// disables the limit. An oversized packet closes the connection because its
// unread body cannot safely remain in the protocol stream.
func WithMaxReadPacketSize(ctx context.Context, size int) context.Context {
	return context.WithValue(ctx, maxReadPacketSizeKey{}, size)
}

func (mc *mysqlConn) applyReadPacketSize(ctx context.Context) func() {
	previous := mc.maxReadPacketSize
	limit, _ := ctx.Value(maxReadPacketSizeKey{}).(int)
	if limit < 0 {
		limit = 0
	}
	mc.maxReadPacketSize = limit
	return func() {
		mc.maxReadPacketSize = previous
	}
}
