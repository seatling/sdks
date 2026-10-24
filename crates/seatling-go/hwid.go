package seatling

/*
#include "seatling.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// GetHWID calculates and returns the hardware anchor identifier string for the current machine.
// Implements the Zero-Prompt Ed25519 Hybrid Hardware Anchor Architecture (V7).
func GetHWID() (string, error) {
	buf := make([]byte, 256)
	copied := C.seatling_hwid_get((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if copied == 0 || int(copied) > len(buf) {
		return "", fmt.Errorf("seatling: failed to obtain hardware identifier")
	}
	return string(buf[:copied]), nil
}

// WeightedScore calculates the fuzzy quorum score between a baseline HWID and a current HWID.
// Score range is 0 to 100. Verification requires threshold >= 70.
// Weight distribution: Motherboard = 35 pts, CPU = 25 pts, Disk = 20 pts, OS UUID = 20 pts.
func WeightedScore(base, curr HWIDComponents) (uint32, error) {
	if hasNul(base.CPU) || hasNul(base.Mobo) || hasNul(base.Disk) || hasNul(base.OSUUID) ||
		hasNul(curr.CPU) || hasNul(curr.Mobo) || hasNul(curr.Disk) || hasNul(curr.OSUUID) {
		return 0, fmt.Errorf("seatling: HWID components must not contain NUL bytes")
	}

	bCPU := C.CString(base.CPU)
	defer C.free(unsafe.Pointer(bCPU))
	bMobo := C.CString(base.Mobo)
	defer C.free(unsafe.Pointer(bMobo))
	bDisk := C.CString(base.Disk)
	defer C.free(unsafe.Pointer(bDisk))
	bOS := C.CString(base.OSUUID)
	defer C.free(unsafe.Pointer(bOS))

	cCPU := C.CString(curr.CPU)
	defer C.free(unsafe.Pointer(cCPU))
	cMobo := C.CString(curr.Mobo)
	defer C.free(unsafe.Pointer(cMobo))
	cDisk := C.CString(curr.Disk)
	defer C.free(unsafe.Pointer(cDisk))
	cOS := C.CString(curr.OSUUID)
	defer C.free(unsafe.Pointer(cOS))

	score := C.seatling_hwid_weighted_score(bCPU, bMobo, bDisk, bOS, cCPU, cMobo, cDisk, cOS)
	return uint32(score), nil
}
