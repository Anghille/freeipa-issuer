package provisioners

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	//"strconv"
	"sync"

	"github.com/anghille/freeipa-client/freeipa"
	api "github.com/anghille/freeipa-issuer/api/v1"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Using sync.Map to store provisioners safely in concurrent environment.
var collection = new(sync.Map)

// FreeIPAPKI is a structure for storing the FreeIPA client, issuer specifications and the name.
type FreeIPAPKI struct {
	client *freeipa.Client
	spec   *api.IssuerSpec

	name string // Unique name for this instance, usually derived from Kubernetes namespaced name
}

// formatCertificate ensures that the certificate string is enclosed within the standard PEM format.
func formatCertificate(cert string) string {
	header := "-----BEGIN CERTIFICATE-----"
	footer := "-----END CERTIFICATE-----"
	if !strings.HasPrefix(cert, header) {
		cert = strings.Join([]string{header, cert}, "\n")
	}
	if !strings.HasSuffix(cert, footer) {
		cert = strings.Join([]string{cert, footer}, "\n")
	}
	return cert
}

// New returns a new provisioner configured with the information in the given issuer.
// It establishes a connection to the FreeIPA server and initializes the FreeIPAPKI structure.
func New(namespacedName types.NamespacedName, spec *api.IssuerSpec, user, password string, insecure bool) (*FreeIPAPKI, error) {
	// Configure the HTTP transport, specifically allowing for insecure TLS connections if required
	tspt := http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	// Connect to FreeIPA server using the provided host, user credentials and transport settings
	client, err := freeipa.Connect(spec.Host, &tspt, user, password)
	if err != nil {
		return nil, err
	}

	// Initialize and return a FreeIPAPKI instance
	p := &FreeIPAPKI{
		name:   fmt.Sprintf("%s.%s", namespacedName.Name, namespacedName.Namespace),
		client: client,
		spec:   spec,
	}

	return p, nil
}

// Load retrieves a provisioner from the collection by its NamespacedName.
// Returns the provisioner and a boolean indicating if it was found.
func Load(namespacedName types.NamespacedName) (*FreeIPAPKI, bool) {
	v, ok := collection.Load(namespacedName)
	if !ok {
		return nil, ok
	}
	p, ok := v.(*FreeIPAPKI)
	return p, ok
}

// Store adds a new provisioner to the collection, identified by its NamespacedName.
func Store(namespacedName types.NamespacedName, provisioner *FreeIPAPKI) {
	collection.Store(namespacedName, provisioner)
}

type CertPem []byte
type CaPem []byte

const certKey = "certificate"

// Sign sends the certificate request (CSR) to the Certificate Authority (CA) and returns the signed certificate.
// It also checks for existence of the host and the service, and if they don't exist, it attempts to add them.
func (s *FreeIPAPKI) Sign(ctx context.Context, cr *certmanager.CertificateRequest) (CertPem, CaPem, error) {
	log := log.FromContext(ctx).WithName("sign").WithValues("request", cr)

	// Decode the CSR
	csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode CSR for signing: %s", err)
	}

	// Check if CSR has a Common Name
	if csr.Subject.CommonName == "" {
		return nil, nil, fmt.Errorf("Request has no common name provided. Please provide a valid CommonName value")
	}

	// Add host if it doesn't exist and AddHost flag is set
	// Continue the code to add a service if it doesn't exist and AddService flag is set
	// Then, send certificate signing request to the FreeIPA server, handle errors, and process the response
	if s.spec.AddHost {
		if _, err := s.client.HostShow(&freeipa.HostShowArgs{Fqdn: csr.Subject.CommonName}, &freeipa.HostShowOptionalArgs{}); err != nil {
			if ipaE, ok := err.(*freeipa.Error); ok && ipaE.Code == freeipa.NotFoundCode {
				if _, err := s.client.HostAdd(&freeipa.HostAddArgs{
					Fqdn: csr.Subject.CommonName,
				}, &freeipa.HostAddOptionalArgs{
					Force: freeipa.Bool(true),
				}); err != nil {
					return nil, nil, fmt.Errorf("fail adding host: %v", err)
				}
			} else {
				return nil, nil, fmt.Errorf("fail getting Host wi: %v", err)
			}
		}
	}

	// Construct a name by concatenating the service name and common name from the CSR.
	name := fmt.Sprintf("%s/%s", s.spec.ServiceName, csr.Subject.CommonName)

	// Check if the service addition is required as per specifications.
	if s.spec.AddService {
		// Try to find the service in FreeIPA using the constructed name.
		svcList, err := s.client.ServiceFind(
			name,
			&freeipa.ServiceFindArgs{},
			&freeipa.ServiceFindOptionalArgs{
				PkeyOnly:  freeipa.Bool(true), // Only retrieve primary key.
				Sizelimit: freeipa.Int(1),     // Limit the search results to 1.
			})

		// If an error occurred and we're not ignoring errors, fail and return.
		if err != nil {
			if !s.spec.IgnoreError {
				return nil, nil, fmt.Errorf("fail listing services: %v", err)
			}
		} else if svcList.Count == 0 {
			// If the service doesn't exist, attempt to add it.
			if _, err := s.client.ServiceAdd(&freeipa.ServiceAddArgs{Krbcanonicalname: name},
				&freeipa.ServiceAddOptionalArgs{Force: freeipa.Bool(true)}); err != nil && !s.spec.IgnoreError {
				return nil, nil, fmt.Errorf("fail adding service: %v", err)
			}
		}
	}

	// Create alias principal for the service if DNSNames is specified
	if csr.DNSNames != nil && len(csr.DNSNames) > 0 {
		for i, v := range csr.DNSNames {
			csr.DNSNames[i] = fmt.Sprintf("%s/%s", s.spec.ServiceName, v)
		}

		log.Info("Adding principal aliases for service")
		if _, err := s.client.ServiceAddPrincipal(
			&freeipa.ServiceAddPrincipalArgs{Krbcanonicalname: name, Krbprincipalname: csr.DNSNames},
			&freeipa.ServiceAddPrincipalOptionalArgs{}); err != nil && !s.spec.IgnoreError {
			return nil, nil, fmt.Errorf("fail adding DNSNames SAN principal to the service %v : %v", name, err)
		} else {
			log.Info("Added DNSNames SAN principal to the service", "service", name)
		}
	}

	// Send certificate signing request (CSR) to the FreeIPA server with the constructed name as principal.
	certRequestResult, err := s.client.CertRequest(&freeipa.CertRequestArgs{
		Csr:       string(cr.Spec.Request),
		Principal: name,
	}, &freeipa.CertRequestOptionalArgs{
		Cacn: &s.spec.Ca,
		Add:  &s.spec.AddPrincipal,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Fail to request certificate: %v", err)
	}

	// Extract the serial number from the certificate request result.
	serialNumberStr, ok := certRequestResult.Result.(map[string]interface{})["serial_number"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("Fail to convert serial_number to string: %v", ok)
	}

	// Construct the certificate show request arguments using the serial number.
	reqCertShow := &freeipa.CertShowArgs{
		SerialNumber: serialNumberStr,
	}

	// Variables to hold the certificate and CA certificate in PEM format.
	var certPem string
	var caPem string

	// Fetch the certificate from the FreeIPA server.
	cert, err := s.client.CertShow(reqCertShow,
		&freeipa.CertShowOptionalArgs{
			Cacn: &s.spec.Ca,
			All:  freeipa.Bool(true)})

	// If there's an error or the certificate chain is empty, fallback to the certificate in the request result.
	if err != nil || len(*cert.Result.CertificateChain) == 0 {
		log.Error(err, "fail to get certificate FALLBACK", "requestResult", certRequestResult)

		c, ok := certRequestResult.Result.(map[string]interface{})[certKey].(string)
		if !ok || c == "" {
			return nil, nil, fmt.Errorf("can't find certificate for: %s", certRequestResult.String())
		}
		certPem = formatCertificate(c)
	} else {
		for i, c := range *cert.Result.CertificateChain {
			if len(strings.Replace(c, "\n", "", -1)) == 0 {
				continue
			}
			c = formatCertificate(c)
			if i == 0 {
				certPem = c
			} else {
				caPem = strings.Join([]string{caPem, c}, "\n\n")
			}
		}
	}

	return []byte(strings.TrimSpace(certPem)), []byte(strings.TrimSpace(caPem)), nil
}
