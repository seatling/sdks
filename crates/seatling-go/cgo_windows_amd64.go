//go:build windows && amd64

package seatling

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -lseatling -lws2_32 -luserenv -lbcrypt -lcrypt32 -ladvapi32 -lntdll
#include "seatling.h"
*/
import "C"
