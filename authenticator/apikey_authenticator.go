package authenticator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rxtech-lab/mcprouter-authenticator/types"
)

type ApikeyAuthenticator struct {
	url        string
	httpClient *http.Client
}

func NewApikeyAuthenticator(url string, httpClient *http.Client) *ApikeyAuthenticator {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &ApikeyAuthenticator{
		url:        url,
		httpClient: httpClient,
	}
}

func (a *ApikeyAuthenticator) Authenticate(serverKey string, userKey string) (*types.User, error) {
	request := types.ApikeyAuthenticationRequest{
		UserKey: userKey,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/auth/mcp/session", a.url), bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", serverKey)

	response, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	// check status code
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentication failed with body: %s", string(responseBody))
	}

	var result types.ApikeyAuthenticationResult
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, err
	}

	return &result.User, nil
}
