module github.com/digitorus/pdfsign

go 1.26.0

require (
	github.com/digitorus/pdf v0.2.0
	github.com/digitorus/pkcs7 v0.0.0-20260821105541-05f79448fa77
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea
	github.com/mattetti/filebuffer v1.0.1
	golang.org/x/crypto v0.55.0
	golang.org/x/image v0.44.0
	golang.org/x/text v0.41.0
)

replace github.com/digitorus/pkcs7 => github.com/alessio-perugini/pkcs7 v0.0.0-20260823190144-e3a5be056941
