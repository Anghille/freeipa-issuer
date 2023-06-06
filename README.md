# FreeIPA Issuer
[![CodeQL](https://github.com/anghille/freeipa-issuer/workflows/CodeQL/badge.svg)](https://github.com/anghille/freeipa-issuer/actions?query=workflow%3ACodeQL)

Forked from [guilhem/freeipa-issuer](https://github.com/guilhem/freeipa-issuer)

A [cert-manager](https://cert-manager.io) external issuer to be used with [FreeIPA](https://www.freeipa.org/). It uses the actively maintained [ccin2p3/go-freeipa](https://github.com/ccin2p3/go-freeipa/tree/master) freeipa client instead of the archived [tehwalris/go-freeipa](https://github.com/tehwalris/go-freeipa).

## Prerequisite

- kubernetes **>=1.22**
- cert-manager **>=1.10**
- [kustomize](https://github.com/kubernetes-sigs/kustomize)
- optional: Kubernetes worker nodes adopted into FreeIPA domain (for use with self signed certificate)

## Install

Create a `kustomization.yaml` file

```bash
mkdir freeipa-issuer
touch freeipa-issuer/kustomization.yaml
vi freeipa-issuer/kustomization.yaml
```

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
metadata:
  name: freeipa-issuer

commonLabels:
  app: freeipa-issuer

resources:
  - https://github.com/anghille/freeipa-issuer/config/default
```

```
# Must be a directory, not the file itself
kubectl apply -k freeipa-issuer/
```

## Delete

To `delete` the ressources, just use:
```
kubectl delete -k freeipa-issuer/
```

## Configuration

Some samples to create the `ClusterIssuer` or `Issuer` can be found [here](config/samples)  
You can `kustomize` your deployment [here](config/default/kustomization.yaml)

### ClusterIssuer

---- 
This YAML file is an example of a ClusterIssuer custom resource based on the FreeIPA issuer code you've provided. Let me explain what each field is for:
* `apiVersion`: Specifies the version of the API that this object should be considered as. This field is used for versioning of the Kubernetes API.
* `kind`: Specifies the type of resource. In this case, it's a ClusterIssuer.
* `metadata`: This section is for data that helps uniquely identify the object, including the name which must be unique within each namespace.
* `spec`: This section defines the desired state of the object:
    * `host`: The hostname of the FreeIPA server.
    * `user`: A reference to a Kubernetes Secret
      * `namespace` (optional): namespace where freeipa-issuer has been deployed
      * `name`: name of the secret
      * `key`: key in the secret containing the username
    * `password`: Similar to user, but contains the password for authenticating to the FreeIPA server
      * `namespace` (optional): namespace where freeipa-issuer has been deployed
      * `name`: name of the secret
      * `key`: key in the secret containing the password
    * `serviceName`: The name of the service to be created in FreeIPA. If not specified, it defaults to HTTP.
    * `addHost`: If true, the issuer will add a host record in FreeIPA for the subject of each certificate it signs.
    * `addService`: If true, the issuer will add a service record in FreeIPA for each certificate it signs.
    * `addPrincipal`: If true, the issuer will add a principal for the service in each certificate it signs.
    * `ca`: The name of the CA in FreeIPA to issue certificates from.
    * `insecure`: If true, the issuer will skip verifying the FreeIPA server's certificate. This is not recommended for production use.
---- 
```yaml
apiVersion: certmanager.freeipa.org/v1beta1
kind: ClusterIssuer
metadata:
  name: freeipa-issuer
spec:
  host: ipa.example.local
  user:
    namespace: freeipa-issuer-system
    name: freeipa-auth
    key: user
  password:
    namespace: freeipa-issuer-system
    name: freeipa-auth
    key: password
  serviceName: HTTP
  addHost: true
  addService: true
  addPrincipal: true
  ca: ipa
  insecure: true
---
apiVersion: v1
kind: Secret
metadata:
  name: freeipa-auth
  namespace: freeipa-issuer-system
data:
  user: Username-in-b64value
  password: Password-in-b64value
```

### Issuer

An issuer is namespaced

```yaml
apiVersion: certmanager.freeipa.org/v1beta1
kind: Issuer
metadata:
  name: issuer-sample
spec:
  host: ipa.example.local
  user:
    name: freeipa-auth
    key: user
  password:
    name: freeipa-auth
    key: password

  # Optionals
  serviceName: HTTP
  addHost: true
  addService: true
  addPrincipal: true
  ca: ipa
  # Do not check certificate of IPA server connection
  insecure: true # unless you can create your own container and inject IPA server CA as trusted.
  # This fixes a bug when adding a service
  ignoreError: true

---
apiVersion: v1
kind: Secret
metadata:
  name: freeipa-auth
data:
  user: Username-in-b64value
  password: Password-in-b64value
```

### Disable Approval Check

The FreeIPA Issuer will wait for CertificateRequests to have an [approved
condition
set](https://cert-manager.io/docs/concepts/certificaterequest/#approval) before
signing. If using an older version of cert-manager (pre v1.3), you can disable
this check by supplying the command line flag `-disable-approved-check` to the
Issuer Deployment.

## Usage

### Cert-Manager

Create a `certificate.yaml`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: you-app-tls
  namespace: your-namespace
spec:
  secretName: the-generated-secret-name-containing-tls-keys
  issuerRef:
    name: freeipa-issuer #replace if you gave your Issuer/ClusterIssuer an other name
    kind: ClusterIssuer # Or Issuer
    group: certmanager.freeipa.org #This is the crds created 
  commonName: "example.local"
  dnsNames:
  - your-app.example.local
```

### Secure an Ingress resource

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: example-ingress
  annotations:
    kubernetes.io/ingress.class: traefik
    #Specify the name of the issuer to use must be in the same namespace
    cert-manager.io/issuer: freeipa-issuer #replace if you gave your Issuer/ClusterIssuer an other name
    #The group of the out of tree issuer is needed for cert-manager to find it
    cert-manager.io/issuer-group: certmanager.freeipa.org
    #Specify a common name for the certificate
    cert-manager.io/common-name: your-app.example.com

spec:
  #placing a host in the TLS config will indicate a certificate should be created
  tls:
    - hosts:
      - your-app.example.com
      #The certificate will be stored in this secret
      secretName: the-generated-secret-name-containing-tls-keys
  rules:
    - host: your-app.example.com
      http:
        paths:
          - path: /
            backend:
              serviceName: backend
              servicePort: 80
```

# Informations

## Dive in the code of freeipa client
For detailed informations about the used functions such as `HostShow`, `HostAdd`, `ServiceAdd`, see [this code](https://raw.githubusercontent.com/ccin2p3/go-freeipa/develop/freeipa/generated.go)

## Detailed steps

Here is what happends when you create a certificate using `freeipa-issuer`:  
  
1. Kubernetes ressources

  A `ClusterIssuer` and `Certificate` resource is created in the Kubernetes cluster, specifying the details of the certificate request. The `ClusterIssuer` contains the information about the `FreeIPA` issuer, like the **hostname**, the **credentials** to use, and other specifics. The `Certificate` resource contains information about the **certificate request**, including the **common name (CN)** and any additional **DNS names** that should be included in the certificate.  
  
2. Cert-manager check loop

  The `cert-manager` controller in the Kubernetes cluster watches for new or updated `Certificate` resources. When it sees the `Certificate` resource created in step 1, it generates a `Certificate Signing Request (CSR)` based on the information in the Certificate resource. It then creates a CertificateRequest resource in the cluster to represent this CSR.  

3. cert-manager to freeipa

  The [FreeIPAPKI](provisionners/freeipa.go) provisioner provided by the `freeipa-issuer`, which also watches for `CertificateRequest` resources in the cluster, sees the `CertificateRequest` resource created in step 2. It gets the CSR data from the CertificateRequest and then proceeds to create the host and service in the `FreeIPA` server, and request the certificate.

```go
// FreeIPAPKI code snippet
type FreeIPAPKI struct {
        client *freeipa.Client
        spec   *api.IssuerSpec

        name string
}
```

4. Certificate signing

  In [FreeIPAPKI.Sign](provisionners/freeipa.go) function, it first decodes the CSR from the `CertificateRequest` and extracts the CN from the CSR. The CN is **expected to be the Fully Qualified Domain Name (FQDN) of the host** for which the certificate is being requested.

```go
// code snipper
func (s *FreeIPAPKI) Sign(ctx context.Context, cr *certmanager.CertificateRequest) (CertPem, CaPem, error) {
        log := log.FromContext(ctx).WithName("sign").WithValues("request", cr)

        csr, err := pki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
```

5. Adding or checking Host

  If the provisioner's spec indicates to add a host (`s.spec.AddHost` is true), it sends a *"host_show"* request to the `FreeIPA` server to check if a host with the extracted FQDN already exists. It uses the s.client.HostShow function for this, passing it the FQDN.  

```go
//snipper of the HostShow function in ccin2p3/go-freeipa repo
  func (c *Client) HostShow(
  reqArgs *HostShowArgs,
  optArgs *HostShowOptionalArgs, // can be nil
) (*HostShowResult, error) {
  if reqArgs == nil {
    return nil, fmt.Errorf("reqArgs cannot be nil")
  }
  kwp := hostShowKwParams{
    HostShowArgs: reqArgs,
    HostShowOptionalArgs: optArgs,
    Version: apiVersion,
  }
  req := request{
    Method: "host_show",
    Params: []interface{}{
      []interface{}{}, &kwp},
  }
  readCloser, e := c.exec(&req)
  if e != nil {
    return nil, e
  }
  defer readCloser.Close()
  var res hostShowResponse
        if e := json.NewDecoder(readCloser).Decode(&res); e != nil {
                return nil, e
        }
        if res.Error != nil {
                return nil, res.Error
        }
  if res.Result == nil {
    return nil, fmt.Errorf("missing result in response")
  }
  return res.Result, nil
}
```

  If the host does not exist (the `FreeIPA` server responds with a *"not found"* error), the provisioner sends a *"host_add"* request to the `FreeIPA` server to add the host. It uses the `s.client.HostAdd` function for this, again passing it the FQDN. If the host addition request encounters an error, the provisioner returns this error and does not proceed further.
  
```go
//snipper of the HostAdd function in ccin2p3/go-freeipa repo
func (c *Client) HostAdd(
  reqArgs *HostAddArgs,
  optArgs *HostAddOptionalArgs, // can be nil
) (*HostAddResult, error) {
  if reqArgs == nil {
    return nil, fmt.Errorf("reqArgs cannot be nil")
  }
  kwp := hostAddKwParams{
    HostAddArgs: reqArgs,
    HostAddOptionalArgs: optArgs,
    Version: apiVersion,
  }
  req := request{
    Method: "host_add",
    Params: []interface{}{
      []interface{}{}, &kwp},
  }
  readCloser, e := c.exec(&req)
  if e != nil {
    return nil, e
  }
  defer readCloser.Close()
  var res hostAddResponse
        if e := json.NewDecoder(readCloser).Decode(&res); e != nil {
                return nil, e
        }
        if res.Error != nil {
                return nil, res.Error
        }
  if res.Result == nil {
    return nil, fmt.Errorf("missing result in response")
  }
  return res.Result, nil
}
```

6. Add or check service

  If the provisioner's spec indicates to add a service (`s.spec.AddService` is true), it sends a *"service_find"* request to the `FreeIPA` server to check if a service with the name specified in the `ClusterIssuer` (`s.spec.ServiceName`) and the host's FQDN already exists.  
  

  If the service does not exist (the `FreeIPA` server responds with zero services found), the provisioner sends a *"service_add"* request to the `FreeIPA` server to add the service. It uses the `s.client.ServiceAdd` function for this, passing it the service's Kerberos Principal Name, which is the service name from the ClusterIssuer combined with the host's FQDN. If the service addition request encounters an error and s.spec.IgnoreError is false, the provisioner returns this error and does not proceed further.

```go
//snipper of the ServiceAdd function in ccin2p3/go-freeipa repo
func (c *Client) ServiceAdd(
  reqArgs *ServiceAddArgs,
  optArgs *ServiceAddOptionalArgs, // can be nil
) (*ServiceAddResult, error) {
  if reqArgs == nil {
    return nil, fmt.Errorf("reqArgs cannot be nil")
  }
  kwp := serviceAddKwParams{
    ServiceAddArgs: reqArgs,
    ServiceAddOptionalArgs: optArgs,
    Version: apiVersion,
  }
  req := request{
    Method: "service_add",
    Params: []interface{}{
      []interface{}{}, &kwp},
  }
  readCloser, e := c.exec(&req)
  if e != nil {
    return nil, e
  }
  defer readCloser.Close()
  var res serviceAddResponse
        if e := json.NewDecoder(readCloser).Decode(&res); e != nil {
                return nil, e
        }
        if res.Error != nil {
                return nil, res.Error
        }
  if res.Result == nil {
    return nil, fmt.Errorf("missing result in response")
  }
  return res.Result, nil
}
```

7. Certificate Request to freeipa
  
  The provisioner sends a *"cert_request"* request to the `FreeIPA` server to request the certificate. It uses the `s.client.CertRequest` function for this, passing it the CSR data and the service's `Kerberos Principal Name`. The `FreeIPA` server should return a response containing the details of the requested certificate. If the certificate request encounters an error, the provisioner returns this error.
  
```go
//snipper of the CertRequest function in ccin2p3/go-freeipa repo
func (c *Client) CertRequest(
  reqArgs *CertRequestArgs,
  optArgs *CertRequestOptionalArgs, // can be nil
) (*CertRequestResult, error) {
  if reqArgs == nil {
    return nil, fmt.Errorf("reqArgs cannot be nil")
  }
  kwp := certRequestKwParams{
    CertRequestArgs: reqArgs,
    CertRequestOptionalArgs: optArgs,
    Version: apiVersion,
  }
  req := request{
    Method: "cert_request",
    Params: []interface{}{
      []interface{}{}, &kwp},
  }
  readCloser, e := c.exec(&req)
  if e != nil {
    return nil, e
  }
  defer readCloser.Close()
  var res certRequestResponse
        if e := json.NewDecoder(readCloser).Decode(&res); e != nil {
                return nil, e
        }
        if res.Error != nil {
                return nil, res.Error
        }
  if res.Result == nil {
    return nil, fmt.Errorf("missing result in response")
  }
  return res.Result, nil
}
```

8. Get the certificate details

  The provisioner sends a *"cert_show"* request to the FreeIPA server to get the certificate details, like the actual **certificate data** and the **expiry date**. It uses the `s.client.CertShow` function for this, passing it the certificate serial number obtained from the previous step. If the certificate show request encounters an error, the provisioner returns this error.
  
```go
//snipper of the CertShow function in ccin2p3/go-freeipa repo
func (c *Client) CertShow(
  reqArgs *CertShowArgs,
  optArgs *CertShowOptionalArgs, // can be nil
) (*CertShowResult, error) {
  if reqArgs == nil {
    return nil, fmt.Errorf("reqArgs cannot be nil")
  }
  kwp := certShowKwParams{
    CertShowArgs: reqArgs,
    CertShowOptionalArgs: optArgs,
    Version: apiVersion,
  }
  req := request{
    Method: "cert_show",
    Params: []interface{}{
      []interface{}{}, &kwp},
  }
  readCloser, e := c.exec(&req)
  if e != nil {
    return nil, e
  }
  defer readCloser.Close()
  var res certShowResponse
        if e := json.NewDecoder(readCloser).Decode(&res); e != nil {
                return nil, e
        }
        if res.Error != nil {
                return nil, res.Error
        }
  if res.Result == nil {
    return nil, fmt.Errorf("missing result in response")
  }
  return res.Result, nil
}
```

9. Updating CertificateRequest in K8S

  Finally, the provisioner updates the CertificateRequest resource in the Kubernetes cluster with the certificate data and status from the FreeIPA server.

10. Creation of the certificate secret

  The `cert-manager controller` in the Kubernetes cluster, still watching the `CertificateRequest` resource, sees the updated certificate data and status. If the status indicates the **certificate request was successful**, cert-manager copies the certificate data to the original Certificate resource, and creates a **Kubernetes Secret** to store the certificate and private key. If the status indicates the certificate request was not successful, **cert-manager marks the Certificate resource as failed**.