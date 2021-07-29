package iamd

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strconv"

	iam "github.com/netsoc/iam/client"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

func apiError(err error) error {
	var iamGeneric iam.GenericOpenAPIError
	if ok := errors.As(err, &iamGeneric); ok {
		if iamError, ok := iamGeneric.Model().(iam.Error); ok {
			return errors.New(iamError.Message)
		}
		return err
	}

	return err
}

// Config holds configuration for Netsoc iamd
type Config struct {
	URL           string `json:"url"`
	Token         string `json:"token"`
	AllowInsecure bool   `json:"allow_insecure"`

	Prompt string `json:"prompt"`
}

// Open returns a connector which can be used to login users through Netsoc iamd
func (c *Config) Open(id string, logger log.Logger) (conn connector.Connector, err error) {
	if c.Token == "" {
		return nil, errors.New("a token must be provided")
	}

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	iamCfg := iam.NewConfiguration()
	if c.URL != "" {
		iamCfg.BasePath = c.URL
	}
	if c.AllowInsecure {
		iamCfg.HTTPClient = insecureClient
	}

	return &iamdConnector{
		token:  c.Token,
		prompt: c.Prompt,

		logger: logger,
		iam:    iam.NewAPIClient(iamCfg),
	}, nil
}

var (
	_ connector.PasswordConnector = (*iamdConnector)(nil)
	_ connector.RefreshConnector  = (*iamdConnector)(nil)
)

type iamdConnector struct {
	token  string
	prompt string

	logger log.Logger
	iam    *iam.APIClient
}

func makeIdentity(u *iam.User, token string) connector.Identity {
	var groups []string
	if u.IsAdmin != nil && *u.IsAdmin {
		groups = append(groups, "admins")
	}

	return connector.Identity{
		UserID:        strconv.Itoa(int(u.Id)),
		Username:      u.Username,
		Email:         u.Email,
		EmailVerified: u.Verified != nil && *u.Verified,

		Groups: groups,

		ConnectorData: []byte(token),
	}
}

func (c *iamdConnector) Prompt() string {
	return c.prompt
}

func (c *iamdConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	r, _, err := c.iam.UsersApi.Login(ctx, username, iam.LoginRequest{Password: password})
	if err != nil {
		err = apiError(err)
		switch err.Error() {
		case "incorrect password":
			return connector.Identity{}, false, nil
		default:
			return connector.Identity{}, false, err
		}
	}

	if _, err := c.iam.UsersApi.ValidateToken(context.WithValue(ctx, iam.ContextAccessToken, r.Token)); err != nil {
		return connector.Identity{}, true, apiError(err)
	}

	u, _, err := c.iam.UsersApi.GetUser(context.WithValue(ctx, iam.ContextAccessToken, c.token), username)
	if err != nil {
		return connector.Identity{}, true, err
	}

	return makeIdentity(&u, r.Token), true, nil
}

func (c *iamdConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	token := string(identity.ConnectorData)
	if _, err := c.iam.UsersApi.ValidateToken(context.WithValue(ctx, iam.ContextAccessToken, token)); err != nil {
		return connector.Identity{}, apiError(err)
	}

	u, _, err := c.iam.UsersApi.GetUser(context.WithValue(ctx, iam.ContextAccessToken, c.token), identity.Username)
	if err != nil {
		return connector.Identity{}, err
	}

	return makeIdentity(&u, token), nil
}
