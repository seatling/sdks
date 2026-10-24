//go:build darwin && arm64

package seatling

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -lseatling -framework CoreFoundation -framework IOKit -framework Security -lpthread -ldl -lm
#include "seatling.h"
*/
import "C"
