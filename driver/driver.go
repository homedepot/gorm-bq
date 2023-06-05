package driver

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/option"
)

type bigQueryDriver struct {
}

type bigQueryConfig struct {
	projectID   string
	location    string
	dataSet     string
	scopes      []string
	endpoint    string
	disableAuth bool
	credentials []byte
}

func (b bigQueryDriver) Open(uri string) (driver.Conn, error) {

	if uri == "scanner" {
		return &scannerConnection{}, nil
	}

	config, err := configFromUri(uri)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	opts := []option.ClientOption{option.WithScopes(config.scopes...)}
	if config.endpoint != "" {
		opts = append(opts, option.WithEndpoint(config.endpoint))
	}
	if config.disableAuth {
		opts = append(opts, option.WithoutAuthentication())
	}
	if config.credentials != nil {
		opts = append(opts, option.WithCredentialsJSON(config.credentials))
	}

	client, err := bigquery.NewClient(ctx, config.projectID, opts...)
	if err != nil {
		return nil, err
	}

	return &bigQueryConnection{
		ctx:    ctx,
		client: client,
		config: *config,
	}, nil
}

func configFromUri(uri string) (*bigQueryConfig, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, invalidConnectionStringError(uri)
	}

	if u.Scheme != "bigquery" {
		return nil, fmt.Errorf("invalid prefix, expected bigquery:// got: %s", uri)
	}

	if u.Path == "" {
		return nil, invalidConnectionStringError(uri)
	}

	fields := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(fields) > 3 {
		return nil, invalidConnectionStringError(uri)
	}
	var decodedCerts []byte
	if len(fields) == 2 {
		//convert base64 encoded string to json byte array
		encCerts := fields[len(fields)-1]
		decodedCert, err := base64.StdEncoding.DecodeString(encCerts)
		if err != nil {
			return nil, fmt.Errorf("invalid cert provided, expected bigquery://projectid/dataset/base64Cert , error : %s ", err)
		}
		decodedCerts = decodedCert

	}

	config := &bigQueryConfig{
		projectID:   u.Hostname(),
		dataSet:     fields[len(fields)-2],
		scopes:      getScopes(u.Query()),
		endpoint:    u.Query().Get("endpoint"),
		disableAuth: u.Query().Get("disable_auth") == "true",
		credentials: decodedCerts,
	}

	if len(fields) == 2 {
		config.location = fields[0]
	}

	return config, nil
}

func getScopes(query url.Values) []string {
	q := strings.Trim(query.Get("scopes"), ",")
	if q == "" {
		return []string{}
	}
	return strings.Split(q, ",")
}

func invalidConnectionStringError(uri string) error {
	return fmt.Errorf("invalid connection string: %s", uri)
}
