default:
	clang -g -O2 -c -target bpf -o main.bpf.o main.bpf.c
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lbpf" go build -o main main.go