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

	response, err := a.httpClient.Post(fmt.Sprintf("%s/api/auth/mcp/session", a.url), "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var result types.ApikeyAuthenticationResult
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, err
	}

	return &result.User, nil
}
