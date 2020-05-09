package main

import (
	"fmt"
)

//go:noinline
func handlerFunction(x int) {
	fmt.Println(x)
}

func main() {
	handlerFunction(3)
}
