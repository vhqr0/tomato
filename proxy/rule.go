package proxy

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
)

const (
	DIR_BLOCK = iota
	DIR_DIRECT
	DIR_FORWARD
)

func (server *Proxy) loadRule() {
	server.ruleCache = make(map[string]int)

	// open rule file
	f, err := os.Open(server.RuleFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	for n := 0; ; n++ {
		// read line
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
			break
		}

		// strip and skip empty or comment line
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// split tokens
		tokens := strings.Split(line, "\t")
		if len(tokens) != 2 {
			log.Fatalf("unrecognized rule in line %d: %s", n, line)
		}
		direction := tokens[0]
		domain := tokens[1]

		// update cache if domain not in cache
		if _, ok := server.ruleCache[domain]; ok {
			continue
		}
		switch direction {
		case "block":
			server.ruleCache[domain] = DIR_BLOCK
		case "direct":
			server.ruleCache[domain] = DIR_DIRECT
		case "forward":
			server.ruleCache[domain] = DIR_FORWARD
		default:
			log.Fatalf("unrecognized direction in line %d: %s", n, direction)
		}
	}
}

func (server *Proxy) matchRule(domain string) int {
	// no rule
	if !server.doMatchRule {
		return server.direction
	}

	// hit in cache
	server.ruleCacheMutex.RLock()
	direction, ok := server.ruleCache[domain]
	server.ruleCacheMutex.RUnlock()
	if ok {
		return direction
	}

	// recursive find in cache
	if pos := strings.IndexByte(domain, '.'); pos == -1 {
		direction = server.direction
	} else {
		direction = server.matchRule(domain[pos+1:])
	}

	// update cache
	server.ruleCacheMutex.Lock()
	server.ruleCache[domain] = direction
	server.ruleCacheMutex.Unlock()

	return direction
}
