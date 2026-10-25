module github.com/cien121/mist-framework/mobile

go 1.26.0

require github.com/cien121/mist-framework/core v0.0.0

require (
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/sys v0.49.0 // indirect
	mist v0.0.0 // indirect
)

replace (
	github.com/cien121/mist-framework/core => ../core
	mist => ../mist
)
