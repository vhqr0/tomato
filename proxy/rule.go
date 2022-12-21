package proxy

import (
	"database/sql"
	"log"
	"strings"
)

const (
	RULE_BLOCK = iota
	RULE_DIRECT
	RULE_FORWARD
)

func (server *Proxy) setupRule() {
	server.ruleCache = make(map[string]int)
	switch server.Direction {
	case "block":
		server.direction = RULE_BLOCK
	case "direct":
		server.direction = RULE_DIRECT
	case "forward":
		server.direction = RULE_FORWARD
	default:
		log.Fatalf("unrecognized rule: %s", server.Direction)
	}
	if len(server.RuleFile) != 0 {
		db, err := sql.Open("sqlite3", server.RuleFile)
		if err != nil {
			log.Fatal(err)
		}
		stmt, err := db.Prepare("select rule from data where domain = ?")
		if err != nil {
			log.Fatal(err)
		}
		server.ruleDb = db
		server.ruleStmt = stmt
	}

}

func (server *Proxy) matchRule(domain string) int {
	// not use rule db
	if server.ruleDb == nil {
		return server.direction
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
			log.Fatalf("unrecognized rule: %s", ruleStr)
		}
	} else if err == sql.ErrNoRows {
		// not hit in db
		pos := strings.IndexByte(domain, '.')
		if pos == -1 {
			// in the end, not match
			rule = server.direction
		} else {
			// recusive match
			rule = server.matchRule(domain[pos+1:])
		}
	} else {
		// db error
		log.Fatal(err)
	}

	// update cache
	server.ruleCacheMutex.Lock()
	server.ruleCache[domain] = rule
	server.ruleCacheMutex.Unlock()

	return rule
}
