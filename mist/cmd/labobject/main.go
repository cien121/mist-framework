// Command labobject is the pilot-only plain HTTP/1.1 object server for
// Stage 3 pilot Tier 1 synthetic matched load. It serves no real content:
// /obj/<bytes> returns deterministically filled bytes, and /page/<id>
// returns the frozen class-A object list as JSON. It is unrelated to
// Mist and must never be pointed at a production address.
//
// Logs record object sizes and timestamps only, never content.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// buildCommit is injected at build time with -ldflags -X main.buildCommit.
var buildCommit = "dev"

// pageObjects is the frozen class-A object list (PLAN §4.1): 32K + 48K +
// 96K + 128K + 256K + 192K + 128K + 8x16K = 1,032,192 bytes (~1.0MB).
var pageObjects = []int{
	32768, 49152, 98304, 131072, 262144, 196608, 131072,
	16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
}

// maxObjBytes caps a single synthetic object at 4MiB.
const maxObjBytes = 4 * 1024 * 1024

// fillByte is the deterministic fill function: byte i of any object is
// fillByte(i), so the same size always yields the same bytes.
func fillByte(i int) byte { return byte((i*31 + 7) & 0xff) }

func objBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fillByte(i)
	}
	return b
}

type pageDoc struct {
	ID      string `json:"id"`
	Objects []int  `json:"objects"`
}

func handleObj(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/obj/"))
	if err != nil || n <= 0 || n > maxObjBytes {
		http.Error(w, "bad object size", http.StatusBadRequest)
		return
	}
	log.Printf("obj size=%d", n)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	_, _ = w.Write(objBytes(n))
}

func handlePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/page/")
	if id == "" {
		http.Error(w, "missing page id", http.StatusBadRequest)
		return
	}
	log.Printf("page id=%s objects=%d", id, len(pageObjects))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pageDoc{ID: id, Objects: pageObjects})
}

func main() {
	listen := flag.String("listen", "10.200.1.2:18080", "TCP listen address (pilot lab address; never a production port)")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", handleObj)
	mux.HandleFunc("/page/", handlePage)
	srv := &http.Server{Addr: *listen, Handler: mux}
	log.Printf("labobject buildCommit=%s listen=%s", buildCommit, *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("labobject: %v", err)
	}
}
