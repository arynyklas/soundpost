//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePG is a PostgreSQL v3 server just good enough to check the three fixture clients (fixtures/nativeperf/runtime/
// pgwait.{mjs,ts,py}): startup with trust, cleartext or an unsupported authentication, the simple Query message, and
// ErrorResponse. It answers each query at once with the value its reply function gives (the real server's sleep is the
// real database's business; what is checked here is the framing and the client's own rules).
type fakePG struct {
	ln       net.Listener
	auth     string // trust, cleartext, md5 or fatal
	password string
	reply    func(sql string) (value, failure string)

	mu      sync.Mutex
	queries []string
	gotPass string
}

func startFakePG(t *testing.T, auth, password string, reply func(string) (string, string)) *fakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePG{ln: ln, auth: auth, password: password, reply: reply}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakePG) addr() string { return f.ln.Addr().String() }

func pgFrame(kind byte, body []byte) []byte {
	out := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(body)+4))
	return append(out, body...)
}

func pgErr(severity, message string) []byte {
	return pgFrame('E', []byte("S"+severity+"\x00M"+message+"\x00\x00"))
}

// pgMaxFrame bounds a frame the fake server reads: the fixture clients send a few hundred bytes at most.
const pgMaxFrame = 1 << 20

// readPGBody reads one frame body whose four-byte length (which counts itself) is the next thing on r. A length taken from the
// wire, or left at zero by a failed read, must never size an allocation: zero minus the four header bytes wraps to 4 GiB, which
// the race detector touches page by page.
func readPGBody(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size < 4 || size-4 > pgMaxFrame {
		return nil, fmt.Errorf("frame length %d", size)
	}
	body := make([]byte, size-4)
	_, err := io.ReadFull(r, body)
	return body, err
}

func (f *fakePG) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	startup, err := readPGBody(r)
	if err != nil || len(startup) < 4 || binary.BigEndian.Uint32(startup[:4]) != 196608 || !bytes.Contains(startup, []byte("user\x00postgres\x00")) {
		return
	}
	switch f.auth {
	case "fatal":
		c.Write(pgErr("FATAL", "no pg_hba.conf entry for host"))
		return
	case "md5":
		c.Write(pgFrame('R', []byte{0, 0, 0, 5, 1, 2, 3, 4}))
		return
	case "cleartext":
		c.Write(pgFrame('R', []byte{0, 0, 0, 3}))
		kind, _ := r.ReadByte()
		body, _ := readPGBody(r) // a client that hung up sent no password: the check below refuses it
		f.mu.Lock()
		f.gotPass = string(bytes.TrimRight(body, "\x00"))
		f.mu.Unlock()
		if kind != 'p' || f.gotPass != f.password {
			c.Write(pgErr("FATAL", "password authentication failed"))
			return
		}
	}
	c.Write(pgFrame('R', []byte{0, 0, 0, 0}))
	c.Write(pgFrame('S', []byte("server_version\x0016.99 (fake)\x00")))
	c.Write(pgFrame('K', []byte{0, 0, 0, 1, 0, 0, 0, 2}))
	c.Write(pgFrame('Z', []byte{'I'}))
	for {
		kind, err := r.ReadByte()
		if err != nil {
			return
		}
		body, err := readPGBody(r)
		if err != nil {
			return
		}
		switch kind {
		case 'X':
			return
		case 'Q':
			sql := string(bytes.TrimRight(body, "\x00"))
			f.mu.Lock()
			f.queries = append(f.queries, sql)
			f.mu.Unlock()
			value, failure := f.reply(sql)
			if failure != "" {
				c.Write(pgErr("ERROR", failure))
				c.Write(pgFrame('Z', []byte{'I'}))
				continue
			}
			desc := append([]byte{0, 1}, []byte("col\x00")...)
			desc = append(desc, make([]byte, 18)...)
			c.Write(pgFrame('T', desc))
			row := []byte{0, 1, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(row[2:], uint32(len(value)))
			c.Write(pgFrame('D', append(row, value...)))
			c.Write(pgFrame('C', []byte("SELECT 1\x00")))
			c.Write(pgFrame('Z', []byte{'I'}))
		}
	}
}

// a pgClientRun is one runtime's driver for the client in its fixture file.
type pgClientRun struct {
	runtime string
	bin     string
	ext     string
	script  func(dir string) string
}

func pgClients(t *testing.T) []pgClientRun {
	t.Helper()
	runtimeDir, err := filepath.Abs("../runtime")
	if err != nil {
		t.Fatal(err)
	}
	var out []pgClientRun
	node := firstELF(os.Getenv("SOUNDPOST_NODE22"), os.Getenv("SOUNDPOST_NODE24"), os.Getenv("SOUNDPOST_NODE"), lookELF("node"))
	if node != "" {
		out = append(out, pgClientRun{"node", node, ".mjs", func(string) string {
			return `import {connectPg,databaseWait} from ` + jsString("file://"+filepath.Join(runtimeDir, "pgwait.mjs")) + `;
const [addr,password]=process.argv.slice(2);
try{const c=await connectPg(addr,{password});const r=await databaseWait(c,3,()=>performance.now());
 console.log(JSON.stringify({version:c.params.server_version,n:r.waitsMs.length,reported:r.reportedS}));c.close();process.exit(0);}
catch(e){console.log("ERR "+e.message);process.exit(1);}
`
		}})
	}
	if bun := bunBinary("../../.."); bun != "" {
		out = append(out, pgClientRun{"bun", bun, ".ts", func(string) string {
			return `import {connectPg,databaseWait} from ` + jsString(filepath.Join(runtimeDir, "pgwait.ts")) + `;
const [addr,password]=process.argv.slice(2);
try{const c=await connectPg(addr,{password});const r=await databaseWait(c,3,()=>performance.now());
 console.log(JSON.stringify({version:c.params.server_version,n:r.waitsMs.length,reported:r.reportedS}));c.close();process.exit(0);}
catch(e){console.log("ERR "+(e as Error).message);process.exit(1);}
`
		}})
	}
	if py := lookELF("python3"); py != "" {
		out = append(out, pgClientRun{"python", py, ".py", func(string) string {
			return `import asyncio, json, sys
sys.path.insert(0, ` + jsString(runtimeDir) + `)
from pgwait import connect_pg, database_wait

async def main():
    addr, password = sys.argv[1], sys.argv[2]
    try:
        c = await connect_pg(addr, password=password)
        waits, reported = await database_wait(c, 3)
        print(json.dumps({"version": c.params.get("server_version"), "n": len(waits), "reported": reported}))
        c.close()
    except Exception as e:
        print("ERR", e)
        sys.exit(1)

asyncio.run(main())
`
		}})
	}
	if len(out) == 0 {
		t.Skip("none of node, bun or python3 is available")
	}
	return out
}

func jsString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// run executes the client against addr and returns what it printed.
func (p pgClientRun) run(t *testing.T, addr, password string) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "client"+p.ext)
	if err := os.WriteFile(script, []byte(p.script(dir)), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, script, addr, password)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		t.Logf("%s stderr: %s", p.runtime, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), err == nil
}

func sleepReply(value string) func(string) (string, string) {
	return func(sql string) (string, string) {
		if strings.Contains(sql, "pg_sleep") {
			return value, ""
		}
		return "1", ""
	}
}

// Each client speaks the protocol to a server that holds the statement the way the real one does: it authenticates
// (trust, or the cleartext password), runs a first statement, and then the three sleeping statements whose own-clock
// account it reads back.
func TestPGWaitClientsSpeakTheWireProtocol(t *testing.T) {
	for _, p := range pgClients(t) {
		t.Run(p.runtime+"/trust", func(t *testing.T) {
			f := startFakePG(t, "trust", "", sleepReply("0.2004"))
			out, ok := p.run(t, f.addr(), "")
			if !ok {
				t.Fatalf("client failed: %s", out)
			}
			var got struct {
				Version  string    `json:"version"`
				N        int       `json:"n"`
				Reported []float64 `json:"reported"`
			}
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("%q: %v", out, err)
			}
			if got.Version != "16.99 (fake)" || got.N != 3 || len(got.Reported) != 3 || got.Reported[0] != 0.2004 {
				t.Errorf("result %+v", got)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.queries) != 4 || f.queries[0] != "select 1" {
				t.Fatalf("queries %q, want the first statement and three sleeping ones", f.queries)
			}
			for _, q := range f.queries[1:] {
				if !strings.Contains(q, "pg_sleep(0.2)") || !strings.Contains(q, "statement_timestamp()") || !strings.Contains(q, "materialized") {
					t.Errorf("sleeping statement %q", q)
				}
			}
		})
		t.Run(p.runtime+"/cleartext", func(t *testing.T) {
			f := startFakePG(t, "cleartext", "s3cret", sleepReply("0.2"))
			if out, ok := p.run(t, f.addr(), "s3cret"); !ok {
				t.Fatalf("client failed with the right password: %s", out)
			}
			if out, ok := p.run(t, f.addr(), ""); ok || !strings.Contains(out, "password") {
				t.Fatalf("a password-less client: %q ok=%v", out, ok)
			}
			if out, ok := p.run(t, f.addr(), "wrong"); ok || !strings.Contains(out, "password authentication failed") {
				t.Fatalf("a client with the wrong password: %q ok=%v", out, ok)
			}
		})
		t.Run(p.runtime+"/failures", func(t *testing.T) {
			for name, tc := range map[string]struct {
				auth, password string
				reply          func(string) (string, string)
				want           string
			}{
				"an authentication method the fixture does not speak": {"md5", "", sleepReply("0.2"), "authentication method 5"},
				"a refusal at startup":                                {"fatal", "", sleepReply("0.2"), "FATAL: no pg_hba.conf entry"},
				"an error of the statement itself": {"trust", "", func(sql string) (string, string) {
					if strings.Contains(sql, "pg_sleep") {
						return "", "canceling statement due to statement timeout"
					}
					return "1", ""
				}, "ERROR: canceling statement due to statement timeout"},
				"a server that did not hold the statement": {"trust", "", sleepReply("0.05"), "less than the 0.2 s"},
			} {
				f := startFakePG(t, tc.auth, tc.password, tc.reply)
				if out, ok := p.run(t, f.addr(), tc.password); ok || !strings.Contains(out, tc.want) {
					t.Errorf("%s: %q ok=%v, want an error containing %q", name, out, ok, tc.want)
				}
			}
		})
		t.Run(p.runtime+"/refused", func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			ln.Close() // nothing listens here any more
			if out, ok := p.run(t, addr, ""); ok || !strings.HasPrefix(out, "ERR") {
				t.Errorf("an unreachable database: %q ok=%v", out, ok)
			}
		})
	}
}

// The fake server must never size an allocation from a frame length it did not read: a client that hangs up before it sends its
// password leaves the length at zero, and zero minus the four header bytes wraps to 4 GiB. The plain build never touches that
// memory, so this test counts the bytes the server asked the heap for; the race detector does touch it (its shadow memory), which
// is how `go test -race` of this package was OOM-killed at 14 GiB on the 6.6.162 qualification VM.
func TestFakePGAsksNothingOfTheHeapForALengthItNeverRead(t *testing.T) {
	f := startFakePG(t, "cleartext", "s3cret", sleepReply("0.2"))
	c, err := net.Dial("tcp", f.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	startup := append([]byte{0, 3, 0, 0}, "user\x00postgres\x00\x00"...)
	hello := make([]byte, 4, 4+len(startup))
	binary.BigEndian.PutUint32(hello, uint32(4+len(startup)))
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := c.Write(append(hello, startup...)); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 9) // 'R', length 8, method 3: the cleartext password request
	if _, err := io.ReadFull(c, auth); err != nil || auth[0] != 'R' || auth[8] != 3 {
		t.Fatalf("no cleartext password request: %v %v", auth, err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil { // hang up without the password
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, c); err != nil { // the server has answered and closed its side
		t.Fatal(err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Fatalf("the server asked the heap for %d bytes while reading a frame that never arrived", grew)
	}
}
