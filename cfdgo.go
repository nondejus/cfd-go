/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.12
 *
 * This file is not intended to be easily readable and contains a number of
 * coding conventions designed to improve portability and efficiency. Do not make
 * changes to this file unless you know what you are doing--modify the SWIG
 * interface file instead.
 * ----------------------------------------------------------------------------- */

// source: src\swig_sandbox.i

package cfdgo

/*
#define intgo swig_intgo
typedef void *swig_voidp;

#include <stdint.h>


typedef int intgo;
typedef unsigned int uintgo;



typedef struct { char *p; intgo n; } _gostring_;
typedef struct { void* array; intgo len; intgo cap; } _goslice_;



#cgo LDFLAGS: -L/usr/local/lib -L${SRCDIR}/build/Release -L${SRCDIR}/build/Debug -lcfd

typedef _gostring_ swig_type_1;
extern void _wrap_Swig_free_cfdgo_c0c6dd295992cb48(uintptr_t arg1);
extern uintptr_t _wrap_Swig_malloc_cfdgo_c0c6dd295992cb48(swig_intgo arg1);
extern swig_intgo _wrap_kCfdSuccess_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdUnknownError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdInternalError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdMemoryFullError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdIllegalArgumentError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdIllegalStateError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdOutOfRangeError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdInvalidSettingError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdConnectionError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdDiskAccessError_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdEnableBitcoin_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_kCfdEnableElements_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_CfdGetSupportedFunction_cfdgo_c0c6dd295992cb48(uintptr_t arg1);
extern swig_intgo _wrap_CfdInitialize_cfdgo_c0c6dd295992cb48(void);
extern swig_intgo _wrap_CfdFinalize_cfdgo_c0c6dd295992cb48(_Bool arg1);
extern swig_intgo _wrap_CfdCreateHandle_cfdgo_c0c6dd295992cb48(swig_voidp arg1);
extern swig_intgo _wrap_CfdFreeHandle_cfdgo_c0c6dd295992cb48(uintptr_t arg1);
extern swig_intgo _wrap_CfdFreeBuffer_cfdgo_c0c6dd295992cb48(uintptr_t arg1);
extern swig_intgo _wrap_CfdFreeStringBuffer_cfdgo_c0c6dd295992cb48(swig_type_1 arg1);
extern swig_intgo _wrap_CfdGetLastErrorCode_cfdgo_c0c6dd295992cb48(uintptr_t arg1);
extern swig_intgo _wrap_CfdGetLastErrorMessage_cfdgo_c0c6dd295992cb48(uintptr_t arg1, swig_voidp arg2);
#undef intgo
*/
import "C"

import "unsafe"
import _ "runtime/cgo"
import "sync"


type _ unsafe.Pointer



var Swig_escape_always_false bool
var Swig_escape_val interface{}


type _swig_fnptr *byte
type _swig_memberptr *byte


type _ sync.Mutex

func Swig_free(arg1 uintptr) {
	_swig_i_0 := arg1
	C._wrap_Swig_free_cfdgo_c0c6dd295992cb48(C.uintptr_t(_swig_i_0))
}

func Swig_malloc(arg1 int) (_swig_ret uintptr) {
	var swig_r uintptr
	_swig_i_0 := arg1
	swig_r = (uintptr)(C._wrap_Swig_malloc_cfdgo_c0c6dd295992cb48(C.swig_intgo(_swig_i_0)))
	return swig_r
}

type Enum_SS_CfdErrorCode int
func _swig_getkCfdSuccess() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdSuccess_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdSuccess Enum_SS_CfdErrorCode = _swig_getkCfdSuccess()
func _swig_getkCfdUnknownError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdUnknownError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdUnknownError Enum_SS_CfdErrorCode = _swig_getkCfdUnknownError()
func _swig_getkCfdInternalError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdInternalError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdInternalError Enum_SS_CfdErrorCode = _swig_getkCfdInternalError()
func _swig_getkCfdMemoryFullError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdMemoryFullError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdMemoryFullError Enum_SS_CfdErrorCode = _swig_getkCfdMemoryFullError()
func _swig_getkCfdIllegalArgumentError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdIllegalArgumentError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdIllegalArgumentError Enum_SS_CfdErrorCode = _swig_getkCfdIllegalArgumentError()
func _swig_getkCfdIllegalStateError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdIllegalStateError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdIllegalStateError Enum_SS_CfdErrorCode = _swig_getkCfdIllegalStateError()
func _swig_getkCfdOutOfRangeError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdOutOfRangeError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdOutOfRangeError Enum_SS_CfdErrorCode = _swig_getkCfdOutOfRangeError()
func _swig_getkCfdInvalidSettingError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdInvalidSettingError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdInvalidSettingError Enum_SS_CfdErrorCode = _swig_getkCfdInvalidSettingError()
func _swig_getkCfdConnectionError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdConnectionError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdConnectionError Enum_SS_CfdErrorCode = _swig_getkCfdConnectionError()
func _swig_getkCfdDiskAccessError() (_swig_ret Enum_SS_CfdErrorCode) {
	var swig_r Enum_SS_CfdErrorCode
	swig_r = (Enum_SS_CfdErrorCode)(C._wrap_kCfdDiskAccessError_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdDiskAccessError Enum_SS_CfdErrorCode = _swig_getkCfdDiskAccessError()
type Enum_SS_CfdLibraryFunction int
func _swig_getkCfdEnableBitcoin() (_swig_ret Enum_SS_CfdLibraryFunction) {
	var swig_r Enum_SS_CfdLibraryFunction
	swig_r = (Enum_SS_CfdLibraryFunction)(C._wrap_kCfdEnableBitcoin_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdEnableBitcoin Enum_SS_CfdLibraryFunction = _swig_getkCfdEnableBitcoin()
func _swig_getkCfdEnableElements() (_swig_ret Enum_SS_CfdLibraryFunction) {
	var swig_r Enum_SS_CfdLibraryFunction
	swig_r = (Enum_SS_CfdLibraryFunction)(C._wrap_kCfdEnableElements_cfdgo_c0c6dd295992cb48())
	return swig_r
}

var KCfdEnableElements Enum_SS_CfdLibraryFunction = _swig_getkCfdEnableElements()
func CfdGetSupportedFunction(arg1 Uint64_t) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1.Swigcptr()
	swig_r = (int)(C._wrap_CfdGetSupportedFunction_cfdgo_c0c6dd295992cb48(C.uintptr_t(_swig_i_0)))
	return swig_r
}

func CfdInitialize() (_swig_ret int) {
	var swig_r int
	swig_r = (int)(C._wrap_CfdInitialize_cfdgo_c0c6dd295992cb48())
	return swig_r
}

func CfdFinalize(arg1 bool) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	swig_r = (int)(C._wrap_CfdFinalize_cfdgo_c0c6dd295992cb48(C._Bool(_swig_i_0)))
	return swig_r
}

func CfdCreateHandle(arg1 *uintptr) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	swig_r = (int)(C._wrap_CfdCreateHandle_cfdgo_c0c6dd295992cb48(C.swig_voidp(_swig_i_0)))
	return swig_r
}

func CfdFreeHandle(arg1 uintptr) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	swig_r = (int)(C._wrap_CfdFreeHandle_cfdgo_c0c6dd295992cb48(C.uintptr_t(_swig_i_0)))
	return swig_r
}

func CfdFreeBuffer(arg1 uintptr) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	swig_r = (int)(C._wrap_CfdFreeBuffer_cfdgo_c0c6dd295992cb48(C.uintptr_t(_swig_i_0)))
	return swig_r
}

func CfdFreeStringBuffer(arg1 string) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	swig_r = (int)(C._wrap_CfdFreeStringBuffer_cfdgo_c0c6dd295992cb48(*(*C.swig_type_1)(unsafe.Pointer(&_swig_i_0))))
	if Swig_escape_always_false {
		Swig_escape_val = arg1
	}
	return swig_r
}

func CfdGetLastErrorCode(arg1 uintptr) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	swig_r = (int)(C._wrap_CfdGetLastErrorCode_cfdgo_c0c6dd295992cb48(C.uintptr_t(_swig_i_0)))
	return swig_r
}

func CfdGetLastErrorMessage(arg1 uintptr, arg2 *string) (_swig_ret int) {
	var swig_r int
	_swig_i_0 := arg1
	_swig_i_1 := arg2
	swig_r = (int)(C._wrap_CfdGetLastErrorMessage_cfdgo_c0c6dd295992cb48(C.uintptr_t(_swig_i_0), C.swig_voidp(_swig_i_1)))
	return swig_r
}


type SwigcptrUint64_t uintptr
type Uint64_t interface {
	Swigcptr() uintptr;
}
func (p SwigcptrUint64_t) Swigcptr() uintptr {
	return uintptr(p)
}

