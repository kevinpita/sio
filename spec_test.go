package sio_test

// Constantes de la especificación (DARE.md, sección 3). Se definen aquí y no
// se toman del paquete sio, para que los valores esperados no dependan del
// código que se está probando.
const (
	headerSize = 16                   // cabecera de cada paquete
	tagSize    = 16                   // tag de autenticación de cada paquete
	overhead   = headerSize + tagSize // bytes que cada paquete añade al texto plano

	maxPayloadSize = 1 << 16 // 64 KiB: payload máximo de un paquete
	maxPackageSize = maxPayloadSize + overhead
	maxPackages    = 1 << 32 // el número de secuencia es un uint32

	maxPlaintextSize  = maxPackages * maxPayloadSize // 2^48 bytes (256 TiB)
	maxCiphertextSize = maxPackages * maxPackageSize
)
