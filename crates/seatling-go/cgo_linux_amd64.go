//go:build linux && amd64

package seatling

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -Wl,--exclude-libs,ALL -L${SRCDIR}/lib/linux_amd64 -lseatling -lpthread -ldl -lm
#include "seatling.h"
*/
import "C"
