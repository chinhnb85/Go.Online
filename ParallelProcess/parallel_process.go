package main

import (
    "fmt"
    "runtime"
	"sync"
	//"time"
)

func main() {
    runtime.GOMAXPROCS(2)

    var wg sync.WaitGroup
    wg.Add(2)

    fmt.Println("Starting Go Routines")
    go func() {
        defer wg.Done()		

        for char := 'a'; char < 'a'+26; char++ {
			fmt.Printf("%c ", char)
			//time.Sleep(1 * time.Second)
        }
    }()

    go func() {
        defer wg.Done()
		
        for number := 1; number < 27; number++ {
			fmt.Printf("%d ", number)
			//time.Sleep(1 * time.Second)
        }
    }()

    fmt.Println("Waiting To Finish")
    wg.Wait()

    fmt.Println("\nTerminating Program")
}