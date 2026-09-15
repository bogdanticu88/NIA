// cmd/niactl is the operator CLI: register an agent, grant or revoke
// permissions, pull the kill switch, restore a killed agent, and
// inspect current state. It talks to cmd/api over HTTP; it holds no
// state of its own and implements no policy logic, everything here is
// a thin wrapper around the control-plane API's HTTP surface.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func apiAddr() string {
	if v := os.Getenv("NIA_API_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

func usage() {
	fmt.Fprintln(os.Stderr, `niactl - NIA operator CLI

Usage:
  niactl register -ref <agent_ref> [-owner <owner>] [-purpose <purpose>]
  niactl list
  niactl kill -ref <agent_ref> -incident <incident_id> [-operator <name>]

Every command talks to the control-plane API (NIA_API_URL, default http://localhost:8080).`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "register":
		cmdRegister(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "kill":
		cmdKill(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	ref := fs.String("ref", "", "canonical agent ref, e.g. agent:billing-reconciler")
	owner := fs.String("owner", "", "human or team accountable for this agent")
	purpose := fs.String("purpose", "", "what this agent is for")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "register: -ref is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"ref":     *ref,
		"owner":   *owner,
		"purpose": *purpose,
	})
	post("/agents", body)
}

func cmdList(_ []string) {
	get("/agents")
}

func cmdKill(args []string) {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to kill")
	incident := fs.String("incident", "", "incident id this kill is tied to")
	operator := fs.String("operator", "niactl", "who is pulling the switch")
	_ = fs.Parse(args)

	if *ref == "" || *incident == "" {
		fmt.Fprintln(os.Stderr, "kill: -ref and -incident are required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"agent_ref": *ref,
		"incident":  *incident,
		"operator":  *operator,
	})
	post("/policy/kill", body)
}

func post(path string, body []byte) {
	resp, err := http.Post(apiAddr()+path, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func get(path string) {
	resp, err := http.Get(apiAddr() + path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func printResponse(resp *http.Response) {
	out, _ := io.ReadAll(resp.Body)
	fmt.Println(string(out))
	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
}
