# FreeIPA Issuer
[![CodeQL](https://github.com/anghille/freeipa-issuer/workflows/CodeQL/badge.svg)](https://github.com/anghille/freeipa-issuer/actions?query=workflow%3ACodeQL)

Forked from [guilhem/freeipa-issuer](https://github.com/guilhem/freeipa-issuer)

A [cert-manager](https://cert-manager.io) external issuer to be used with [FreeIPA](https://www.freeipa.org/). It uses the actively maintained anghille/freeipa-client instead of the archived [tehwalris/go-freeipa](https://github.com/tehwalris/go-freeipa).

## Prerequisite

- kubernetes **>=1.22**
- cert-manager **>=1.10**
- [kustomize](https://github.com/kubernetes-sigs/kustomize)
- optional: Kubernetes worker nodes adopted into FreeIPA domain (for use with self signed certificate)

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
