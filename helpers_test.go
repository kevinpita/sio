package sio_test

// outcome junta valor y error para comprobarlos con una sola aserción compuesta.
type outcome[T any] struct {
	Value T
	Err   error
}
