package main

import (
	"fmt"
	"time"
)

//go:noinline
func function(x int) {
	fmt.Println(x)
	time.Sleep(time.Second)
	fmt.Println("It's February 2nd!")
}

func main() {
	function(3)
}
