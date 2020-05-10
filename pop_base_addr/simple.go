package main

import (
	"fmt"
	"time"
)

//go:noinline
func function() {
	time.Sleep(time.Second)
	fmt.Println("It's February 2nd!")
}

func main() {
	function()
}
