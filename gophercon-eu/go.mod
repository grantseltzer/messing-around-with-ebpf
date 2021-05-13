module github.com/grantseltzer/fucking-around-with-ebpf/gophercon-eu

go 1.16

replace github.com/aquasecurity/libbpfgo => /home/vagrant/go/src/github.com/aquasecurity/tracee/libbpfgo

require (
	github.com/aquasecurity/libbpfgo v0.0.0-00010101000000-000000000000
	github.com/aquasecurity/tracee/libbpfgo v0.0.0-20210513142145-242d721bad3d // indirect
)
