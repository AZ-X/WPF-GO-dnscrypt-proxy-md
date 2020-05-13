//+build cgo

package main


import (
	"stammel/stammel"
	"unsafe"
)
/*
#include <stdio.h>
#include <stdlib.h>
*/
import "C"


//var _= stammel.EXP_CreateSign
//var _= stammel.EXP_CheckSignature
var _= stammel.EXP_ReadStamp
func main() {
}

//export EXP_Free
func EXP_Free(ptr unsafe.Pointer) {
	C.free(ptr)
}
