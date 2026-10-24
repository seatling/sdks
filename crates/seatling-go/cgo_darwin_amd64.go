//go:build darwin && amd64

package seatling

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -lseatling -framework CoreFoundation -framework IOKit -framework Security -lpthread -ldl -lm
#include "seatling.h"
*/
import "C"
