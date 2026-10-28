//go:build linux && arm64

package seatling

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -lseatling -lpthread -ldl -lm
#include "seatling.h"
*/
import "C"
