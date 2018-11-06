/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clients

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/gravitational/gravity/lib/constants"
	"github.com/gravitational/gravity/lib/defaults"
	"github.com/gravitational/gravity/lib/ops"
	"github.com/gravitational/gravity/lib/utils"

	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/client"
	teledefaults "github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/sshutils"

	"github.com/cloudflare/cfssl/csr"
	"github.com/gravitational/license/authority"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// Teleport returns a new teleport client
func Teleport(operator ops.Operator, proxyHost string) (*client.TeleportClient, error) {
	cluster, err := operator.GetLocalSite()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	auth, tlsConfig, err := authenticateWithTeleport(operator, cluster)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return client.NewClient(&client.Config{
		Username:        constants.OpsCenterUser,
		AuthMethods:     auth,
		SkipLocalAuth:   true,
		HostLogin:       defaults.SSHUser,
		WebProxyAddr:    fmt.Sprintf("%v:%v", proxyHost, defaults.GravityServicePort),
		SSHProxyAddr:    fmt.Sprintf("%v:%v", proxyHost, teledefaults.SSHProxyListenPort),
		SiteName:        cluster.Domain,
		HostKeyCallback: sshHostCheckerAcceptAny,
		TLS:             tlsConfig,
		Env: map[string]string{
			defaults.PathEnv: defaults.PathEnvVal,
		},
	})
}

// TeleportProxy returns a new teleport proxy client
func TeleportProxy(ctx context.Context, operator ops.Operator, proxyHost string) (*client.ProxyClient, error) {
	teleport, err := Teleport(operator, proxyHost)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return teleport.ConnectToProxy(ctx)
}

func authenticateWithTeleport(operator ops.Operator, cluster *ops.Site) ([]ssh.AuthMethod, *tls.Config, error) {
	keygen, err := native.New()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	private, public, err := keygen.GenerateKeyPair("")
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	csr, key, err := authority.GenerateCSR(csr.CertificateRequest{
		CN:    constants.OpsCenterUser,
		Names: []csr.Name{{O: defaults.SystemAccountOrg}},
	}, private)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	response, err := operator.SignSSHKey(ops.SSHSignRequest{
		User:          constants.OpsCenterUser,
		AccountID:     cluster.AccountID,
		PublicKey:     public,
		TTL:           defaults.CertTTL,
		AllowedLogins: []string{defaults.SSHUser},
		CSR:           csr,
	})
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	signer, err := sshutils.NewSigner(private, response.Cert)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	var tlsConfig *tls.Config
	if len(response.TLSCert) != 0 {
		tlsConfig, err = utils.MakeTLSClientConfig(response.TLSCert, key, response.CACert)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, tlsConfig, nil
}

// func getTLSConfig(operator ops.Operator, clusterName string) (*tls.Config, error) {
// 	csr, key, err := authority.GenerateCSR(csr.CertificateRequest{
// 		CN: constants.OpsCenterUser,
// 		Names: []csr.Name{{
// 			O: defaults.SystemAccountOrg,
// 		}},
// 	}, nil)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	response, err := operator.SignTLSKey(ops.TLSSignRequest{
// 		AccountID:  defaults.SystemAccountID,
// 		SiteDomain: clusterName,
// 		CSR:        csr,
// 	})
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	tlsConfig := teleutils.TLSConfig(nil)
// 	tlsCert, err := tls.X509KeyPair(response.Cert, key)
// 	if err != nil {
// 		return nil, trace.Wrap(err)
// 	}
// 	pool := x509.NewCertPool()
// 	pool.AppendCertsFromPEM(response.CACert)
// 	tlsConfig.Certificates = []tls.Certificate{tlsCert}
// 	tlsConfig.RootCAs = pool
// 	return tlsConfig, nil
// }

func sshHostCheckerAcceptAny(hostId string, remote net.Addr, key ssh.PublicKey) error {
	return nil
}
