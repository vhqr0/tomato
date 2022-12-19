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

const (
	RULE_BLOCK = iota
	RULE_DIRECT
	RULE_FORWARD
)

type Proxy struct {
	LogTrace  bool
	Forward   bool
	RuleMode  string
	RuleFile  string
	LocalAddr string
	PeerAddr  string

	ruleCache      map[string]int
	ruleCacheMutex sync.RWMutex
	ruleDefault    int
	ruleDb         *sql.DB
	ruleStmt       *sql.Stmt
	directClient   http.Client
	forwardClient  http.Client
}

func (server *Proxy) matchRule(domain string) int {
	// not use rule db
	if server.ruleDb == nil {
		return server.ruleDefault
	}

	// hit in cache
	server.ruleCacheMutex.RLock()
	rule, ok := server.ruleCache[domain]
	server.ruleCacheMutex.RUnlock()
	if ok {
		return rule
	}

	// query db
	var ruleStr string
	err := server.ruleStmt.QueryRow(domain).Scan(&ruleStr)
	if err == nil {
		// hit in db
		switch ruleStr {
		case "block":
			rule = RULE_BLOCK
		case "direct":
			rule = RULE_DIRECT
		case "forward":
			rule = RULE_FORWARD
		default:
			rule = server.ruleDefault
			log.Printf("unrecognized rule: %s", ruleStr)
		}
	} else if err == sql.ErrNoRows {
		// not hit in db
		pos := strings.IndexByte(domain, '.')
		if pos == -1 {
			// in the end, not match
			rule = server.ruleDefault
		} else {
			// recusive match
			rule = server.matchRule(domain[pos+1:])
		}
	} else {
		// db error
		log.Println(err)
		rule = server.ruleDefault
	}

	// update cache
	server.ruleCacheMutex.Lock()
	server.ruleCache[domain] = rule
	server.ruleCacheMutex.Unlock()

	return rule
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
			log.Printf("unrecognized rule: %d", rule)
		}
		log.Printf("%v %v <=> %v [%s]", r.Method, r.RemoteAddr, r.Host, ruleStr)
	}

	if rule == RULE_BLOCK {
		return
	}

	if r.Method == http.MethodConnect {
		// do connect
		var addr string
		if rule == RULE_DIRECT || !server.Forward {
			addr = r.Host
		} else {
			addr = server.PeerAddr
		}
		srvconn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Println(err)
			return
		}
		defer srvconn.Close()

		// hijack
		hj, ok := w.(http.Hijacker)
		if !ok {
			log.Println("get hijacker failed")
			return
		}
		cliconn, _, err := hj.Hijack()
		if err != nil {
			log.Println(err)
			return
		}
		defer cliconn.Close()

		// relay
		if rule == RULE_DIRECT || !server.Forward {
			cliconn.Write([]byte(r.Proto + " 200 OK\r\n\r\n"))
		} else {
			srvconn.Write([]byte(fmt.Sprintf(
				"CONNECT %s %s\r\nHost: %s\r\n\r\n",
				r.Host, r.Proto, r.Host)))
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(srvconn, cliconn)
		}()
		go func() {
			defer wg.Done()
			io.Copy(cliconn, srvconn)
		}()
		wg.Wait()

	} else {

		// make request
		req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			log.Println(err)
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
		if rule == RULE_DIRECT || !server.Forward {
			client = &server.directClient
		} else {
			client = &server.forwardClient
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Println(err)
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
	// setup rule matcher
	server.ruleCache = make(map[string]int)
	switch server.RuleMode {
	case "block":
		server.ruleDefault = RULE_BLOCK
	case "direct":
		server.ruleDefault = RULE_DIRECT
	case "forward":
		server.ruleDefault = RULE_FORWARD
	default:
		log.Printf("unrecognized rule: %s", server.RuleMode)
		return
	}
	if len(server.RuleFile) != 0 {
		db, err := sql.Open("sqlite3", server.RuleFile)
		if err != nil {
			log.Println(err)
			return
		}
		defer db.Close()
		stmt, err := db.Prepare("select rule from data where domain = ?")
		if err != nil {
			log.Println(err)
			return
		}
		defer stmt.Close()
		server.ruleDb = db
		server.ruleStmt = stmt
	}

	// setup forward client
	if server.Forward {
		proxyURL, err := url.Parse("http://" + server.PeerAddr)
		if err != nil {
			log.Println(err)
			return
		}
		server.forwardClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	log.Println(http.ListenAndServe(server.LocalAddr, server))
}
