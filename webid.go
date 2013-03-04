package main

import (
	"net/http"
	"io/ioutil"
	"fmt"
	"turtle/parse"
)

type tripple struct {
	subject, predicate, object string
}

func main() {
	//resp, err := http.Get("http://selfdual.com/webid#me")
	resp, err := http.Get("http://localhost:4000/webid#me")
	if err != nil {
		panic("error")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic("error")
	}
	var tripples []tripple
	ch := parse.Parse("test", string(body))
	for v := range ch {
		tripples = append(tripples, tripple{v.Object, v.Predicate, v.Subject})
	}

	for _, t := range tripples {
		//if t.Object dd== "<>"
		fmt.Println(t)
	}

	fmt.Println("OK")
}
