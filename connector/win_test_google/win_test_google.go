// Package win_test_google implements logging in through Google's OpenID Connect provider.
package win_test_google

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/dexidp/dex/connector"
	pkg_groups "github.com/dexidp/dex/pkg/groups"
)

const (
	issuerURL = "https://accounts.google.com"
)

// Config holds configuration options for Google logins.
type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// Optional list of whitelisted domains
	// If this field is nonempty, only users from a listed domain will be allowed to log in
	HostedDomains []string `json:"hostedDomains"`

	// Optional list of whitelisted groups
	// If this field is nonempty, only users from a listed group will be allowed to log in
	Groups []string `json:"groups"`

	// Optional
	// If non empty string, then only members of this group will be allowed to log in
	// the different with "Groups" option above, this option dont remove any gruop from the lists
	LimitAccessToGroup string `json:"limitAccessToGroup"`

	// Optional path to service account json
	// If nonempty, and groups claim is made, will use authentication from file to
	// check groups with the cloudidentity api
	ServiceAccountFilePath string `json:"serviceAccountFilePath"`

	// Required if ServiceAccountFilePath
	// The admin email and customerID for searching groups transitively
	AdminConfig []adminConfig `json:"adminConfig"`

	// Optional value for the prompt parameter, defaults to consent when offline_access
	// scope is requested
	PromptType *string `json:"promptType"`
}

type adminConfig struct {
	Email      string `json:"email"`
	CustomerID string `json:"customerID"`
}

// Open returns a connector which can be used to login users through Google.
func (c *Config) Open(id string, logger *slog.Logger) (conn connector.Connector, err error) {
	logger = logger.With(slog.Group("connector", "type", "win_test_google", "id", id))
	ctx, cancel := context.WithCancel(context.Background())

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	cloudIDSvc := []cloudIDSvc{}

	for _, config := range c.AdminConfig {
		srv, err := createIdentityService(c.ServiceAccountFilePath, config, logger)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("could not create cloudidentity service: %v", err)
		}

		cloudIDSvc = append(cloudIDSvc, srv)
	}

	promptType := "consent"
	if c.PromptType != nil {
		promptType = *c.PromptType
	}

	clientID := c.ClientID
	return &googleConnector{
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{ClientID: clientID},
		),
		logger:                 logger,
		cancel:                 cancel,
		hostedDomains:          c.HostedDomains,
		groups:                 c.Groups,
		limitAccessToGroup:     c.LimitAccessToGroup,
		serviceAccountFilePath: c.ServiceAccountFilePath,
		cloudIDSvc:             cloudIDSvc,
		promptType:             promptType,
	}, nil
}

var (
	_ connector.CallbackConnector = (*googleConnector)(nil)
	_ connector.RefreshConnector  = (*googleConnector)(nil)
)

type cloudIDSvc struct {
	customerID string
	email      string
	svc        *cloudidentity.Service
}

type googleConnector struct {
	redirectURI            string
	oauth2Config           *oauth2.Config
	verifier               *oidc.IDTokenVerifier
	cancel                 context.CancelFunc
	logger                 *slog.Logger
	hostedDomains          []string
	groups                 []string
	limitAccessToGroup     string
	serviceAccountFilePath string
	cloudIDSvc             []cloudIDSvc
	promptType             string
}

func (c *googleConnector) Close() error {
	c.cancel()
	return nil
}

func (c *googleConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	var opts []oauth2.AuthCodeOption
	if len(c.hostedDomains) > 0 {
		preferredDomain := c.hostedDomains[0]
		if len(c.hostedDomains) > 1 {
			preferredDomain = "*"
		}
		opts = append(opts, oauth2.SetAuthURLParam("hd", preferredDomain))
	}

	if s.OfflineAccess {
		opts = append(opts, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", c.promptType))
	}

	return c.oauth2Config.AuthCodeURL(state, opts...), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *googleConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}
	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("google: failed to get token: %v", err)
	}

	return c.createIdentity(r.Context(), identity, token)
}

func (c *googleConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	t := &oauth2.Token{
		RefreshToken: string(identity.ConnectorData),
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.oauth2Config.TokenSource(ctx, t).Token()
	if err != nil {
		return identity, fmt.Errorf("google: failed to get token: %v", err)
	}

	return c.createIdentity(ctx, identity, token)
}

func (c *googleConnector) createIdentity(ctx context.Context, identity connector.Identity, token *oauth2.Token) (connector.Identity, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("google: no id_token in token response")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("google: failed to verify ID Token: %v", err)
	}

	var claims struct {
		Username      string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		HostedDomain  string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
	}

	if len(c.hostedDomains) > 0 {
		found := false
		for _, domain := range c.hostedDomains {
			if claims.HostedDomain == domain {
				found = true
				break
			}
		}

		if !found {
			return identity, fmt.Errorf("oidc: unexpected hd claim %v", claims.HostedDomain)
		}
	}

	var groups []string
	if c.limitAccessToGroup != "" || len(c.groups) > 0 { // if need to fetch google group
		groups, err = c.getGroups(claims.Email)
		if err != nil {
			return identity, fmt.Errorf("google: could not retrieve groups: %v", err)
		}
	}

	if c.limitAccessToGroup != "" {
		if !slices.Contains(groups, c.limitAccessToGroup) {
			return identity, fmt.Errorf("google: user %q is not in %q", claims.Username, c.limitAccessToGroup)
		}
	}

	if len(c.groups) > 0 {
		groups = pkg_groups.Filter(groups, c.groups)
		if len(groups) == 0 {
			return identity, fmt.Errorf("google: user %q is not in any of the required groups", claims.Username)
		}
	}

	identity = connector.Identity{
		UserID:        idToken.Subject,
		Username:      claims.Username,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		ConnectorData: []byte(token.RefreshToken),
		Groups:        groups,
	}
	return identity, nil
}

// createIdentityService sets up super user impersonation and creates an admin client for calling
// the google cloudidentity api. If no serviceAccountFilePath is defined, the application default credential
// is used.
func createIdentityService(serviceAccountFilePath string, adminConfig adminConfig, logger *slog.Logger) (svc cloudIDSvc, err error) {
	var jsonCredentials []byte

	ctx := context.Background()
	if serviceAccountFilePath == "" {
		logger.Warn("the application default credential is used since the service account file path is not used")
		jsonCredentials, svc, err = getCredentialsFromDefault(ctx, adminConfig, logger)
		if err != nil {
			return
		}
		if svc.svc != nil {
			return
		}
	} else {
		jsonCredentials, err = getCredentialsFromFilePath(serviceAccountFilePath)
		if err != nil {
			return
		}
	}
	config, err := google.JWTConfigFromJSON(jsonCredentials, cloudidentity.CloudIdentityGroupsReadonlyScope)
	if err != nil {
		return svc, fmt.Errorf("unable to parse client secret file to config: %v", err)
	}

	config.Subject = adminConfig.Email

	internalSvc, err := cloudidentity.NewService(ctx, option.WithHTTPClient(config.Client(ctx)))
	if err != nil {
		return svc, err
	}

	return cloudIDSvc{
		customerID: adminConfig.CustomerID,
		email:      adminConfig.Email,
		svc:        internalSvc,
	}, nil
}

// getGroups creates a connection to the cloudidentity service and lists
// all groups the user is a member of
func (c *googleConnector) getGroups(email string) ([]string, error) {
	userGroups := make(map[string]struct{})

eachAdminLoop:
	for _, svc := range c.cloudIDSvc {
		var err error
		var res *cloudidentity.SearchTransitiveGroupsResponse

		for {
			nextToken := ""
			if res != nil {
				nextToken = res.NextPageToken
			}
			res, err = svc.svc.Groups.Memberships.
				SearchTransitiveGroups("groups/-").
				Query(fmt.Sprintf("parent == 'customers/%s' && member_key_id == '%s'", svc.customerID, email)).
				PageToken(nextToken).
				Do()
			if err != nil {
				c.logger.Warn(fmt.Sprintf("could not search transitive groups for %s using admin %s: %v", email, svc.email, err.Error()))
				continue eachAdminLoop
			}

			for _, group := range res.Memberships {
				userGroups[group.GroupKey.Id] = struct{}{}
			}

			if res.NextPageToken == "" {
				break
			}
		}
	}

	var result []string
	for group := range userGroups {
		result = append(result, group)
	}
	return result, nil
}

// getCredentialsFromFilePath reads and returns the service account credentials from the file at the provided path.
// If an error occurs during the read, it is returned.
func getCredentialsFromFilePath(serviceAccountFilePath string) ([]byte, error) {
	jsonCredentials, err := os.ReadFile(serviceAccountFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading credentials from file: %v", err)
	}
	return jsonCredentials, nil
}

// getCredentialsFromDefault retrieves the application's default credentials.
// If the default credential is empty, it attempts to create a new service with metadata credentials.
// If successful, it returns the service and nil error.
// If unsuccessful, it returns the error and a nil service.
func getCredentialsFromDefault(ctx context.Context, adminConfig adminConfig, logger *slog.Logger) (ret []byte, svc cloudIDSvc, err error) {
	credential, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return ret, svc, fmt.Errorf("failed to fetch application default credentials: %w", err)
	}

	if credential.JSON == nil {
		logger.Info("JSON is empty, using flow for GCE")
		svc, err = createServiceWithMetadataServer(ctx, adminConfig, logger)
		if err != nil {
			return ret, svc, err
		}
		return nil, svc, nil
	}

	return credential.JSON, svc, nil
}

// createServiceWithMetadataServer creates a new service using metadata server.
// If an error occurs during the process, it is returned along with a nil service.
func createServiceWithMetadataServer(ctx context.Context, adminConfig adminConfig, logger *slog.Logger) (svc cloudIDSvc, err error) {
	serviceAccountEmail, err := metadata.EmailWithContext(ctx, "default")
	logger.Info("discovered serviceAccountEmail", "email", serviceAccountEmail)

	if err != nil {
		return svc, fmt.Errorf("unable to get service account email from metadata server: %v", err)
	}

	config := impersonate.CredentialsConfig{
		TargetPrincipal: serviceAccountEmail,
		Scopes:          []string{cloudidentity.CloudIdentityGroupsReadonlyScope},
		Lifetime:        0,
		Subject:         adminConfig.Email,
	}

	tokenSource, err := impersonate.CredentialsTokenSource(ctx, config)
	if err != nil {
		return svc, fmt.Errorf("unable to impersonate with %s, error: %v", adminConfig.Email, err)
	}

	internalSvc, err := cloudidentity.NewService(ctx, option.WithHTTPClient(oauth2.NewClient(ctx, tokenSource)))
	if err != nil {
		return svc, err
	}
	return cloudIDSvc{
		customerID: adminConfig.CustomerID,
		email:      adminConfig.Email,
		svc:        internalSvc,
	}, nil

}
