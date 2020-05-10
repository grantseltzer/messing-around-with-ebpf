Compile each one seperately:

`go build simple.go`
`go build tracer.go`

Try running `./simple`

Then try `sudo ./tracer ./simple`, and running `./simple` again.

Dependencies:
- bcc
- kernel 4.14+