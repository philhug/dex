package connector

import (
	"html/template"
	"net/http"
	"net/url"
	"path"
	"time"

	phttp "github.com/coreos/dex/pkg/http"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
        "github.com/RobotsAndPencils/go-saml"
)

const (
	SAMLConnectorType = "saml"
	samlHttpPathCallback  = "/callback"
)

func init() {
	RegisterConnectorConfigType(SAMLConnectorType, func() ConnectorConfig { return &SAMLConnectorConfig{} })
}

type SAMLConnectorConfig struct {
	ID                   string `json:"id"`
	IssuerURL            string `json:"issuerURL"`
	SPIssuerURL          string `json:"spIssuerURL"`
	IDPSSOURL            string `json:"idpSSOURL"`
	IDPPublicCertPath    string `json:"idpPublicCertPath"`
	IDPIdAttribute       string `json:"idpIdAttribute"`
	TrustedEmailProvider bool   `json:"trustedEmailProvider"`
}

func (cfg *SAMLConnectorConfig) ConnectorID() string {
	return cfg.ID
}

func (cfg *SAMLConnectorConfig) ConnectorType() string {
	return SAMLConnectorType
}

type SAMLConnector struct {
	id                   string
	issuerURL            string
	cbURL                url.URL
	loginFunc            oidc.LoginFunc
        spSettings           saml.ServiceProviderSettings
	idAttribute          string
	trustedEmailProvider bool
}

func (cfg *SAMLConnectorConfig) Connector(ns url.URL, lf oidc.LoginFunc, tpls *template.Template) (Connector, error) {
	ns.Path = path.Join(ns.Path, samlHttpPathCallback)

        // Configure the app and account settings
        sp := saml.ServiceProviderSettings{
           IDPSSOURL:                   cfg.IDPSSOURL,
           IDPSSODescriptorURL:         cfg.SPIssuerURL,
           IDPPublicCertPath:           cfg.IDPPublicCertPath,
           AssertionConsumerServiceURL: ns.String(),
        }
        sp.Init()

	idpc := &SAMLConnector{
		id:                   cfg.ID,
		issuerURL:            cfg.IssuerURL,
		cbURL:                ns,
		loginFunc:            lf,
                spSettings:           sp,
                idAttribute:          cfg.IDPIdAttribute,
		trustedEmailProvider: cfg.TrustedEmailProvider,
	}
	return idpc, nil
}

func (c *SAMLConnector) ID() string {
	return c.id
}

func (c *SAMLConnector) Healthy() error {
	return nil //c.client.Healthy()
}

func (c *SAMLConnector) LoginURL(sessionKey, prompt string) (string, error) {
        // Construct an AuthnRequest
        var sp = c.spSettings;

        authnRequest := sp.GetAuthnRequest()
        b64XML, err := authnRequest.CompressedEncodedString()
        if err != nil {
          return "", err
        }

        // for convenience, get a URL formed with the SAMLRequest parameter
        url, err := saml.GetAuthnRequestURL(sp.IDPSSOURL, b64XML, sessionKey)
        if err != nil {
          return "", err
        }

        return url,err
}

func (c *SAMLConnector) Register(mux *http.ServeMux, errorURL url.URL) {
	mux.Handle(c.cbURL.Path, c.handleCallbackFunc(c.loginFunc, errorURL))
}

func (c *SAMLConnector) Sync() chan struct{} {
	return nil //c.client.SyncProviderConfig(c.issuerURL)
}

func (c *SAMLConnector) TrustedEmailProvider() bool {
	return c.trustedEmailProvider
}

func samlRedirectError(w http.ResponseWriter, errorURL url.URL, q url.Values) {
	redirectURL := phttp.MergeQuery(errorURL, q)
	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (c *SAMLConnector) handleCallbackFunc(lf oidc.LoginFunc, errorURL url.URL) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		encodedXML := r.FormValue("SAMLResponse")
		if encodedXML == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "SAMLResponse missing")
			redirectError(w, errorURL, q)
			return
		}

		if encodedXML == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
		    q.Set("error_description", "SAMLResponse form value missing")
			redirectError(w, errorURL, q)
			return
		    return
		}

		response, err := saml.ParseEncodedResponse(encodedXML)
		if err != nil {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "SAMLResponse parse: "+err.Error())
			redirectError(w, errorURL, q)
			return
		}

		err = response.Validate(&c.spSettings)
		if err != nil {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "SAMLResponse validation: "+err.Error())
			redirectError(w, errorURL, q)
			return
		}

		samlID := response.GetAttribute(c.idAttribute)
		if samlID == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "SAML attribute identifier uid missing")
			redirectError(w, errorURL, q)
			return
		}

		ident := new (oidc.Identity)
		ident.ID = samlID
		ident.ExpiresAt, err = time.Parse(time.RFC3339, response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter)
		if err != nil {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "SAMLResponse validation: "+err.Error())
			redirectError(w, errorURL, q)
			return
		}

		sessionKey := r.FormValue("RelayState")
		if sessionKey == "" {
			q.Set("error", oauth2.ErrorInvalidRequest)
			q.Set("error_description", "missing state query param")
			redirectError(w, errorURL, q)
			return
		}

		redirectURL, err := lf(*ident, sessionKey)
		if err != nil {
			log.Errorf("Unable to log in %#v: %v", *ident, err)
			q.Set("error", oauth2.ErrorAccessDenied)
			q.Set("error_description", "login failed")
			redirectError(w, errorURL, q)
			return
		}

		w.Header().Set("Location", redirectURL)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
}
