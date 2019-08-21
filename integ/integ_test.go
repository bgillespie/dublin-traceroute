package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// WARNING: this test is meant to run on CI, don't run it on your production
// machines or it will mess up your iptables rules.

const NfQueueNum int64 = 101

var (
	// TODO detect this at start-up
	needSudo = true

	defaultDubTrTimeout = 10 * time.Second
)

// isCI returns true if the environment is a CI like Travis-CI or CircleCI,
// false otherwise.
func isCI() bool {
	return os.Getenv("CI") == "true"
}

func setup() {
	if isCI() {
		cl := []string{"iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "33434:33634", "-d", "8.8.8.8", "-j", "NFQUEUE", "--queue-num", strconv.FormatInt(NfQueueNum, 10)}
		if needSudo {
			cl = append([]string{"sudo"}, cl...)
		}
		if err := exec.Command(cl[0], cl[1:]...).Run(); err != nil {
			log.Panicf("Failed to run iptables: %v", err)
		}
	}
}

func shutdown() {
	// nothing to do here
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

type testConfig struct {
	// timeout for dublin-traceroute
	timeout time.Duration
	// arguments to routest
	configFile string
	// arguments to dublin-traceroute
	paths   *int
	minTTL  *int
	maxTTL  *int
	srcPort *int
	dstPort *int
	delay   *int
	target  string
}

// sudoKill sends a signal to the given PID, as root. This is useful when
// sending signals to a process started under a different user.
func sudoKill(pid int, sigNum os.Signal, killSession bool) error {
	if pid == 0 {
		log.Printf("sudoKill: pid is 0, nothing to do")
		return nil
	}
	if pid <= 0 {
		// nothing to do: if 0, the Process object is not initialized. If
		// -1, it has been already killed
		log.Printf("sudoKill: proc has already been killed, nothing to do")
		return nil
	}
	pidToKill := pid
	if killSession {
		sid, err := unix.Getsid(pid)
		if err != nil {
			return fmt.Errorf("sudoKill: getsid for pid %d failed: %v", pid, err)
		}
		pidToKill = sid
	}
	pidStr := strconv.FormatInt(int64(pidToKill), 10)
	sigStr := strconv.FormatInt(int64(sigNum.(syscall.Signal)), 10)
	// dragons ahead! Here we assume that we are going to kill the right
	// process, and that the PID has not been reused.
	cmd := exec.Command("sudo", "kill", "-"+sigStr, pidStr)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	log.Printf("Sending signal %s to PID %s", sigStr, pidStr)
	return cmd.Run()
}

type routest struct {
	path string
	proc *os.Process
}

// Start starts routest in background.
func (r *routest) Start(asRoot bool, args ...string) error {
	argv := append([]string{r.path}, args...)
	attr := os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Foreground: false,
			Setsid:     true,
		},
	}
	if asRoot {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return errors.New("cannot find sudo in PATH")
		}
		argv = append([]string{sudo, "-b"}, argv...)
	}
	log.Printf("Running routest as %v", argv)
	child, err := os.StartProcess(argv[0], argv, &attr)
	if err != nil {
		return err
	}
	r.proc = child
	return nil
}

func (r *routest) Wait() error {
	if r.proc == nil {
		return errors.New("routest was not started")
	}
	pState, err := r.proc.Wait()
	if err != nil {
		return err
	}
	if pState.ExitCode() != 0 {
		return fmt.Errorf("routest failed with code %d", pState.ExitCode())
	}
	return nil
}

// Kill terminates routest and any of its child processes.
func (r *routest) Kill(asRoot bool) error {
	if r.proc == nil {
		return errors.New("routest was not started")
	}
	if !asRoot {
		return r.proc.Kill()
	}
	return sudoKill(r.proc.Pid, os.Kill, true)
}

func runWithConfig(cfg testConfig) ([]byte, []byte, error) {
	// validate to config
	if cfg.timeout <= 0 {
		cfg.timeout = defaultDubTrTimeout
	}

	// run routest
	riCmd := exec.Command("go", "install", "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/cmd/routest")
	riCmd.Stdout, riCmd.Stderr = os.Stdout, os.Stderr
	if err := riCmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("Cannot install routest: %v", err)
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	/*
		cl := []string{path.Join(gopath, "bin/routest"), "-i", "lo", "-c", cfg.configFile, "-q", strconv.FormatInt(NfQueueNum, 10)}
		if needSudo {
			cl = append([]string{"sudo"}, cl...)
		}
		rCmd := exec.Command(cl[0], cl[1:]...)
		rCmd.Stdout, rCmd.Stderr = os.Stdout, os.Stderr
		defer func() {
			// we cannot kill processes started under a different user, so neither
			// CommandContext nor rCmd.Process.Kill() will work. Literally need to
			// exec "sudo kill <PID>"
			log.Printf("Sending kill signal to routest")
			if err := sudoKill(rCmd.Process.Pid, os.Kill, true); err != nil {
				log.Panicf("Failed to kill routest process with PID %d: %v", rCmd.Process.Pid, err)
			}
		}()
		// using Start instead of Run so the new process is a session leader and its
		// process tree can be terminated easily later on.
		if err := rCmd.Start(); err != nil {
			// don't panic if routests is killed, it's probably us
			if !strings.Contains(err.Error(), "signal: killed") {
				log.Panicf("Error returned from command %+v: %v", rCmd, err)
			}
		}
	*/
	routest := routest{
		path: path.Join(gopath, "bin/routest"),
	}
	args := []string{"-i", "lo", "-c", cfg.configFile, "-q", strconv.FormatInt(NfQueueNum, 10)}
	if err := routest.Start(needSudo, args...); err != nil {
		log.Panicf("Failed to start routest: %v", err)
	}
	go func() {
		if err := routest.Wait(); err != nil {
			log.Panicf("routest failed: %v", err)
		}
	}()
	// give it a moment to start
	// TODO do something better than waiting
	time.Sleep(time.Second)

	// run dublin-traceroute
	errCh := make(chan error, 1)

	traceFile := "trace.json"
	cl := []string{}
	if needSudo {
		cl = append([]string{"sudo"}, cl...)
	}
	cl = append(cl, "../build/dublin-traceroute")
	if cfg.paths != nil {
		cl = append(cl, "-n", strconv.FormatInt(int64(*cfg.paths), 10))
	}
	if cfg.minTTL != nil {
		cl = append(cl, "-t", strconv.FormatInt(int64(*cfg.minTTL), 10))
	}
	if cfg.maxTTL != nil {
		cl = append(cl, "-T", strconv.FormatInt(int64(*cfg.maxTTL), 10))
	}
	if cfg.srcPort != nil {
		cl = append(cl, "-s", strconv.FormatInt(int64(*cfg.srcPort), 10))
	}
	if cfg.dstPort != nil {
		cl = append(cl, "-d", strconv.FormatInt(int64(*cfg.dstPort), 10))
	}
	if cfg.delay != nil {
		cl = append(cl, "-D", strconv.FormatInt(int64(*cfg.delay), 10))
	}
	cl = append(cl, "-o", traceFile)
	cl = append(cl, cfg.target)
	dCmd := exec.Command(cl[0], cl[1:]...)
	var outWriter bytes.Buffer
	dCmd.Stdout, dCmd.Stderr = &outWriter, os.Stderr
	go func() {
		log.Printf("Calling dublin-traceroute with: %v", dCmd)
		errCh <- dCmd.Run()
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return nil, nil, fmt.Errorf("failed call to dublin-traceroute: %v", err)
		}
		break
	case <-time.After(cfg.timeout):
		return nil, nil, fmt.Errorf("dublin-traceroute timed out after %s", cfg.timeout)
	}
	trace, err := ioutil.ReadFile(traceFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot read trace file %s: %v", traceFile, err)
	}
	return outWriter.Bytes(), trace, nil
}

func requireEqualResults(t *testing.T, got, want *results.Results) {
	for wantK, wantV := range want.Flows {
		require.Contains(t, got.Flows, wantK)
		gotV := got.Flows[wantK]
		require.Equal(t, len(wantV), len(gotV))
		for idx := 0; idx < len(wantV); idx++ {
			wantReply, gotReply := wantV[idx], gotV[idx]
			// skip FlowHash, Name, NatID
			require.Equal(t, wantReply.IsLast, gotReply.IsLast)
			// accept 20 msec of difference
			require.InDelta(t, wantReply.RttUsec, gotReply.RttUsec, 20000.)
			// match Sent packet, ignoring Timestamp, IP.SrcIP
			require.NotNil(t, gotReply.Sent, "Sent is nil")
			require.NotNil(t, gotReply.Sent.IP, "Sent.IP not nil")
			require.Equal(t, wantReply.Sent.IP.DstIP, gotReply.Sent.IP.DstIP, "Sent.IP.DstIP")
			require.Equal(t, wantReply.Sent.IP.ID, gotReply.Sent.IP.ID, "Sent.IP.ID")
			require.Equal(t, wantReply.Sent.IP.TTL, gotReply.Sent.IP.TTL, "Sent.IP.TTL")
			require.Equal(t, wantReply.Sent.UDP, gotReply.Sent.UDP, "Sent.UDP")
			// ICMP should be nil
			require.Nil(t, gotReply.Sent.ICMP, "Sent.ICMP not nil")
			// match Received packet, ignoring Timestamp, IP.DstIP, IP.ID,
			// IP.TTL
			require.NotNil(t, gotReply.Received, "Received is nil")
			require.NotNil(t, gotReply.Received.IP, "Received.IP is nil")
			require.Equal(t, wantReply.Received.IP.SrcIP, gotReply.Received.IP.SrcIP, "Received.IP.SrcIP")
			// UDP should be nil
			require.Equal(t, wantReply.Received.UDP, gotReply.Received.UDP, "Received.UDP")
			require.Nil(t, gotReply.Received.UDP, "Received.UDP is not nil")
			require.Equal(t, wantReply.Received.ICMP, gotReply.Received.ICMP, "Received.ICMP")
			require.Equal(t, wantReply.ZeroTTLForwardingBug, gotReply.ZeroTTLForwardingBug, "ZeroTTLForwardingBug")
		}
	}
}

func testCompareResults(t *testing.T, testName string, numPaths int) {
	wantJSON, err := ioutil.ReadFile(fmt.Sprintf("test_data/want_%s.json", testName))
	require.NoError(t, err)
	c := testConfig{
		configFile: fmt.Sprintf("test_data/config_%s.json", testName),
		paths:      &numPaths,
		target:     "8.8.8.8",
	}
	_, gotJSON, err := runWithConfig(c)
	require.NoError(t, err)
	var want, got results.Results
	err = json.Unmarshal(wantJSON, &want)
	require.NoError(t, err)
	err = json.Unmarshal(gotJSON, &got)
	require.NoError(t, err)
	require.Equal(t, len(want.Flows), len(got.Flows))
	requireEqualResults(t, &got, &want)
}

func TestGoogleDNSOnePath(t *testing.T) {
	testCompareResults(t, "8.8.8.8_one_path", 1)
}

func TestGoogleDNSTwoPaths(t *testing.T) {
	testCompareResults(t, "8.8.8.8_two_paths", 2)
}
