// Command payload prints corpus payloads for the eval script (run.sh).
//
//	go run ./test/injection/eval/payload -list            names, one per line
//	go run ./test/injection/eval/payload -name NAME       the payload text
//	go run ./test/injection/eval/payload -canaries        every canary, one per line
//
// It only writes to stdout and never touches a cluster.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/astawiany/k8s-mcp/test/injection/corpus"
)

func main() {
	list := flag.Bool("list", false, "print payload names")
	canaries := flag.Bool("canaries", false, "print every canary string")
	name := flag.String("name", "", "print the text of this payload")
	flag.Parse()
	switch {
	case *list:
		for _, p := range corpus.Payloads() {
			fmt.Println(p.Name)
		}
	case *canaries:
		for _, c := range corpus.Canaries() {
			fmt.Println(c)
		}
	case *name != "":
		p, ok := corpus.ByName(*name)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown payload %q (see -list)\n", *name)
			os.Exit(2)
		}
		fmt.Print(p.Text)
	default:
		flag.Usage()
		os.Exit(2)
	}
}
