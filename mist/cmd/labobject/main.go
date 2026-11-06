// Command labobject is the pilot-only plain HTTP/1.1 object server for
// Stage 3 pilot Tier 1 synthetic matched load. It serves no real content:
// /obj/<bytes> returns deterministically filled bytes, and /page/<id>
// returns the frozen class-A object list as JSON. It is unrelated to
// Mist and must never be pointed at a production address.
//
// -page-delay (V7-A M-page arm) delays the /page/ body by the given
// duration; default 0 (no delay, unchanged behavior).
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
	"time"
)

// buildCommit is injected at build time with -ldflags -X main.buildCommit.
var buildCommit = "dev"

// pageObjects is the frozen class-A object list (PLAN §4.1): 32K + 48K +
// 96K + 128K + 256K + 192K + 128K + 8x16K = 1,032,192 bytes (~1.0MB).
var pageObjects = []int{
	32768, 49152, 98304, 131072, 262144, 196608, 131072,
	16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384,
}

// V7-A M-core phase layouts (design §2.1). The frozen page above cannot
// realize either phase on its own (its min/max ratio is 16K/256K = 1/16,
// and its tail is eight fast objects, not one slow object), so the two
// layouts below are selected by page id. Any other id (including "a")
// returns the frozen page, unchanged.
//
// fullObjects (P-full, "full"): 8 objects, min 64K >= max 256K / 4, so
// four concurrent streams stay in flight for most of the run.
var fullObjects = []int{
	65536, 98304, 131072, 131072, 196608, 262144, 196608, 131072,
}

// tailObjects (P-tail, "tail"): 3 fast objects + 1 slow object. All four
// start concurrently; the 16K objects finish early and the 256K object
// then delivers alone for most of the run, degenerating the aggregate
// detector to single-stream behavior.
var tailObjects = []int{
	16384, 16384, 16384, 262144,
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

// pageDelay is the -page-delay flag value: how long handlePage waits
// before encoding the page body. Zero means no delay. The wait honors
// the request context, so a cancelled client does not pin the handler.
var pageDelay time.Duration

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
	objects := pageObjects
	switch id {
	case "full":
		objects = fullObjects
	case "tail":
		objects = tailObjects
	}
	log.Printf("page id=%s objects=%d", id, len(objects))
	w.Header().Set("Content-Type", "application/json")
	if pageDelay > 0 {
		select {
		case <-time.After(pageDelay):
		case <-r.Context().Done():
			return
		}
	}
	_ = json.NewEncoder(w).Encode(pageDoc{ID: id, Objects: objects})
}

func main() {
	listen := flag.String("listen", "10.200.1.2:18080", "TCP listen address (pilot lab address; never a production port)")
	flag.DurationVar(&pageDelay, "page-delay", 0, "delay before the /page/ body is encoded (V7-A M-page arm; 0 = no delay)")
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
