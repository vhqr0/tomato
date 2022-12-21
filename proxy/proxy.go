package proxy

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type Proxy struct {
	LogTrace    bool
	LocalAddr   string
	ForwardAddr string
	Direction   string
	RuleFile    string

	direction      int
	doForward      bool
	ruleCache      map[string]int
	ruleCacheMutex sync.RWMutex
	ruleDb         *sql.DB
	ruleStmt       *sql.Stmt
	directClient   http.Client
	forwardClient  http.Client
}

func (server *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	rule := server.matchRule(r.URL.Hostname())

	// trace
	if server.LogTrace {
		var ruleStr string
		switch rule {
		case RULE_BLOCK:
			ruleStr = "block"
		case RULE_DIRECT:
			ruleStr = "direct"
		case RULE_FORWARD:
			ruleStr = "forward"
		default:
			log.Fatalf("unrecognized rule: %d", rule)
		}
		log.Printf("%v %v <=> %v [%s]", r.Method, r.RemoteAddr, r.Host, ruleStr)
	}

	if rule == RULE_BLOCK {
		return
	}

	if r.Method == http.MethodConnect {
		// do connect
		var addr string
		if server.doForward && rule == RULE_FORWARD {
			addr = server.ForwardAddr
		} else {
			addr = r.Host
		}
		srvconn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Print(err)
			return
		}
		defer srvconn.Close()

		// hijack
		hj, ok := w.(http.Hijacker)
		if !ok {
			log.Fatal("get hijacker failed")
		}
		cliconn, _, err := hj.Hijack()
		if err != nil {
			log.Fatal(err)
		}
		defer cliconn.Close()

		if server.doForward && rule == RULE_FORWARD {
			// forward request to proxy, proxy will send response
			srvconn.Write([]byte(fmt.Sprintf(
				"CONNECT %s %s\r\nHost: %s\r\n\r\n",
				r.Host, r.Proto, r.Host)))
		} else {
			// send response
			cliconn.Write([]byte(r.Proto + " 200 OK\r\n\r\n"))
		}

		// relay
		ch := make(chan struct{})
		go func() {
			io.Copy(cliconn, srvconn)
			ch <- struct{}{} // done

		}()
		io.Copy(srvconn, cliconn)
		<-ch // wait done

	} else {

		// make request
		req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			log.Print(err)
			return
		}
		for k, vs := range r.Header {
			if strings.HasPrefix(k, "Proxy-") {
				continue
			}
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}

		// do request
		var client *http.Client
		if server.doForward && rule == RULE_FORWARD {
			client = &server.forwardClient
		} else {
			client = &server.directClient
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Print(err)
			return
		}
		defer resp.Body.Close()

		// do response
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func (server *Proxy) ListenAndServe() {
	server.doForward = len(server.ForwardAddr) != 0

	server.setupRule()

	// setup forward client
	if server.doForward {
		proxyURL, err := url.Parse("http://" + server.ForwardAddr)
		if err != nil {
			log.Fatal(err)
		}
		server.forwardClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	log.Fatal(http.ListenAndServe(server.LocalAddr, server))
}
