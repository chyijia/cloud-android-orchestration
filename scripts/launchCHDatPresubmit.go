package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"

	hoapi "github.com/google/android-cuttlefish/frontend/src/host_orchestrator/api/v1"
	apiv1 "github.com/google/cloud-android-orchestration/api/v1"
	app "github.com/google/cloud-android-orchestration/pkg/app"
	CloudOrchestrationClient "github.com/google/cloud-android-orchestration/pkg/client"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2/google"
)

const (
	ServiceURL     = "http://{CO_IP:port}/v1/zones/local" // change this
	proxy          = "socks5://localhost:1337"            // change this if needed
	chunkSizeBytes = 16 * 1024 * 1024

	credentialsFilepath = "../service_key.json" // change this if needed
)

type BuildInfo struct {
	BuildID     string
	BuildTarget string
}

type EnvConfig struct {
	Vendor BuildInfo
	System BuildInfo
}

type CreateCHDRequest struct {
	SystemBuildURL string `json:"system"`
	VendorBuildURL string `json:"vendor"`
	Username       string `json:"username"`
	AccessToken    string `json:"token,omitempty"`
}

func errPrint(msg string) {
	fmt.Printf(msg)
	os.Exit(1)
}

func createConfig(system, vendor BuildInfo) (map[string]interface{}, error) {
	configTemplate := `{
	"instances": [{
		"@import": "phone",
		"vm": {
			"memory_mb": 8192,
			"setupwizard_mode": "OPTIONAL",
			"cpus": 4
		},
		"disk": {
			"default_build": "@ab/{{.Vendor.BuildID}}/{{.Vendor.BuildTarget}}",
			"super_partition": {
				"system": "@ab/{{.System.BuildID}}/{{.System.BuildTarget}}"
			},
			"download_target_files_zip": true,
			"otatools": "@ab/{{.Vendor.BuildID}}/{{.Vendor.BuildTarget}}"
		}
	}]
}
`
	tmpl, err := template.New("").Parse(configTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing template error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, EnvConfig{Vendor: vendor, System: system}); err != nil {
		return nil, fmt.Errorf("executing template error: %w", err)
	}

	var config map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &config)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}

	return config, nil
}

func urlToBuildInfo(urlStr string) (*BuildInfo, error) {
	re := regexp.MustCompile(`^https:\/\/android-build\.corp\.google\.com\/build_explorer\/build_details\/[P0-9][0-9]*\/[0-9A-Za-z_-]*\/$`)
	if re.Match([]byte(urlStr)) {
		strs := strings.Split(urlStr, "/")
		buildID, buildTarget := strs[5], strs[6]
		return &BuildInfo{BuildID: buildID, BuildTarget: buildTarget}, nil
	} else {
		return nil, fmt.Errorf("uri not match, cannot extract build info from uri")
	}
}

func replyJSON(w http.ResponseWriter, obj any, statusCode int) error {
	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
	}
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	return encoder.Encode(obj)
}

func jwtOAuth() (string, error) {
	content, err := os.ReadFile(credentialsFilepath)
	if err != nil {
		return "", fmt.Errorf("cannot read content from credential filepath %s: %w", credentialsFilepath, err)
	}
	jwtConfig, err := google.JWTConfigFromJSON(content, "https://www.googleapis.com/auth/androidbuild.internal")
	if err != nil {
		return "", err
	}
	tk, err := jwtConfig.TokenSource(context.Background()).Token()
	if err != nil {
		return "", err
	}
	return tk.AccessToken, nil
}

func create(req CreateCHDRequest, u chan string) error {
	serviceOpts := &CloudOrchestrationClient.ServiceOptions{
		RootEndpoint:   ServiceURL,
		ProxyURL:       proxy,
		ChunkSizeBytes: chunkSizeBytes,
		Authn: &CloudOrchestrationClient.AuthnOpts{
			HTTPBasic: &CloudOrchestrationClient.HTTPBasic{
				Username: req.Username,
			},
		},
	}
	service, err := CloudOrchestrationClient.NewService(serviceOpts)
	if err != nil {
		return fmt.Errorf("create service error: %w", err)
	}

	// Create host
	createHostReq := &apiv1.CreateHostRequest{
		HostInstance: &apiv1.HostInstance{},
	}
	createHostRes, err := service.CreateHost(createHostReq)
	if err != nil {
		return fmt.Errorf("failed to create host: %w", err)
	}
	hostID := createHostRes.Name
	fmt.Println(hostID)

	// TODO: trasnform the URLs to BuildInfos
	system, err := urlToBuildInfo(req.SystemBuildURL)
	if err != nil {
		return fmt.Errorf("failed to extract system build id and build target from url: %w", err)
	}
	vendor, err := urlToBuildInfo(req.VendorBuildURL)
	if err != nil {
		return fmt.Errorf("failed to extract vendor build id and build target from url: %w", err)
	}

	// create config file
	config, err := createConfig(*system, *vendor)
	if err != nil {
		return fmt.Errorf("create config from build url error: %s", err)
	}

	// create CHD and get the url
	createReq := &hoapi.CreateCVDRequest{
		EnvConfig: config,
	}
	_, err = service.HostService(hostID).CreateCVD(createReq, req.AccessToken)
	if err != nil {
		return fmt.Errorf("create cvd error: %w", err)
	}

	u <- fmt.Sprintf("%s/hosts/%s/", ServiceURL, hostID)
	return nil
}

func CreateHandler(w http.ResponseWriter, r *http.Request) error {
	var req CreateCHDRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		replyJSON(w, fmt.Errorf("Parsing JSON from request body error: %w", err), http.StatusBadRequest)
		return err
	}

	if req.AccessToken == "" {
		req.AccessToken, err = jwtOAuth()
		if err != nil {
			replyJSON(w, fmt.Errorf("JWT Auth error: %w", err), http.StatusBadRequest)
			return fmt.Errorf("JWT Auth error: %w", err)
		}
	}
	url := make(chan string, 1)
	go func(url chan string, w *http.ResponseWriter) {
		err := create(req, url)
		if err != nil {
			log.Fatalln(err)
		}
	}(url, &w)
	res := fmt.Sprintf("Instance created, access here: %s", <-url)
	replyJSON(w, res, http.StatusOK)

	return nil
}

func main() {
	router := mux.NewRouter()
	router.Handle("/create", app.HTTPHandler(CreateHandler)).Methods("POST")

	http.Handle("/", router)
	http.ListenAndServe(":30052", nil)
}
