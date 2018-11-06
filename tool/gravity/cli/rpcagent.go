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

package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gravitational/gravity/lib/constants"
	"github.com/gravitational/gravity/lib/defaults"
	"github.com/gravitational/gravity/lib/fsm"
	"github.com/gravitational/gravity/lib/loc"
	"github.com/gravitational/gravity/lib/localenv"
	"github.com/gravitational/gravity/lib/ops"
	"github.com/gravitational/gravity/lib/pack"
	"github.com/gravitational/gravity/lib/rpc"
	pb "github.com/gravitational/gravity/lib/rpc/proto"
	rpcserver "github.com/gravitational/gravity/lib/rpc/server"
	"github.com/gravitational/gravity/lib/storage"
	"github.com/gravitational/gravity/lib/update"
	"github.com/gravitational/gravity/lib/utils"

	"github.com/cenkalti/backoff"
	teleclient "github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/trace"
	"github.com/gravitational/version"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
)

var cDialTimeout = 1 * time.Second

func rpcAgentInstall(env *localenv.LocalEnvironment, args []string) error {
	gravityPath, err := os.Executable()
	if err != nil {
		return trace.Wrap(err, "failed to determine gravity executable path")
	}

	return trace.Wrap(reinstallOneshotService(env,
		defaults.GravityRPCAgentServiceName,
		append([]string{gravityPath, "--debug", "agent", "run"}, args...)))
}

// rpcAgentRun runs a local agent executing the function specified with optional args
func rpcAgentRun(localEnv, upgradeEnv *localenv.LocalEnvironment, args []string) error {
	server, err := startAgent()
	if err != nil {
		return trace.Wrap(err)
	}

	if len(args) == 0 {
		return trace.Wrap(server.Serve())
	}

	ctx := context.TODO()

	agentFunc, exists := agentFunctions[args[0]]
	if !exists {
		return trace.NotFound("no such function %q", args[0])
	}

	go func(handler string, args []string) {
		log.Infof("Executing function %q.", handler)
		err = agentFunc(ctx, localEnv, upgradeEnv, args)
		if err != nil {
			log.Infof("Error executing function %q: %q", handler, trace.DebugReport(err))
		}
	}(args[0], args[1:])

	return trace.Wrap(server.Serve())
}

func startAgent() (rpcserver.Server, error) {
	secretsDir, err := fsm.AgentSecretsDir()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	serverCreds, clientCreds, err := rpc.Credentials(secretsDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	serverAddr := fmt.Sprintf(":%v", defaults.GravityRPCAgentPort)
	listener, err := net.Listen("tcp4", serverAddr)
	if err != nil {
		return nil, trace.Wrap(err, "failed to bind to %v")
	}

	config := rpcserver.Config{
		Credentials: rpcserver.Credentials{
			Server: serverCreds,
			Client: clientCreds,
		},
		Listener: listener,
	}
	server, err := rpcserver.New(config, logrus.StandardLogger())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.Infof("Starting RPC agent on %v.", listener.Addr().String())

	return server, nil
}

type agentFunc func(ctx context.Context, localEnv, upgradeEnv *localenv.LocalEnvironment, args []string) error

var agentFunctions map[string]agentFunc = map[string]agentFunc{
	constants.RpcAgentUpgradeFunction: executeAutomaticUpgrade,
}

// isOldTeleport returns true if the provided cluster runs an legacy version of Teleport
func isOldTeleport(cluster *ops.Site) (bool, error) {
	teleportPackage, err := cluster.App.Manifest.Dependencies.ByName(constants.TeleportPackage)
	if err != nil {
		return false, trace.Wrap(err)
	}
	teleportVer, err := teleportPackage.SemVer()
	if err != nil {
		return false, trace.Wrap(err)
	}
	return teleportVer.Major < 3, nil
}

func deployAgentsLegacy(env *localenv.LocalEnvironment, cluster *ops.Site, leaderParams []string) error {
	gravityPackage, err := cluster.App.Manifest.Dependencies.ByName(constants.GravityPackage)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Infof("Deploying agents using %v.", gravityPackage)
	// download gravity binary from local cluster
	packages, err := env.ClusterPackages()
	if err != nil {
		return trace.Wrap(err)
	}
	_, reader, err := packages.ReadPackage(*gravityPackage)
	if err != nil {
		return trace.Wrap(err)
	}
	defer reader.Close()
	binary, err := os.OpenFile("/tmp/gravity", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return trace.Wrap(err)
	}
	_, err = io.Copy(binary, reader)
	if err != nil {
		binary.Close()
		return trace.Wrap(err)
	}
	binary.Close()
	args := append([]string{"/tmp/gravity", "agent", "deploy"}, leaderParams...)
	out, err := utils.RunCommand(context.TODO(), log, args...)
	if err != nil {
		return trace.Wrap(err, "%s", string(out))
	}
	log.Infof("Deployed agents: %s.", string(out))
	return nil
}

func rpcAgentDeploy(env *localenv.LocalEnvironment, leaderParams []string) error {
	ctx := context.TODO()

	clusterEnv, err := env.NewClusterEnvironment()
	if err != nil {
		return trace.Wrap(err)
	}

	operator, err := env.SiteOperator()
	if err != nil {
		return trace.Wrap(err)
	}

	cluster, err := operator.GetLocalSite()
	if err != nil {
		return trace.Wrap(err)
	}

	oldTeleport, err := isOldTeleport(cluster)
	if err != nil {
		return trace.Wrap(err)
	}

	if oldTeleport {
		return deployAgentsLegacy(env, cluster, leaderParams)
	}

	teleportClient, err := env.TeleportClient(constants.Localhost)
	if err != nil {
		return trace.Wrap(err, "failed to create a teleport client")
	}

	proxy, err := teleportClient.ConnectToProxy(ctx)
	if err != nil {
		return trace.Wrap(err, "failed to connect to teleport proxy")
	}

	req := deployAgentsRequest{
		clusterState: cluster.ClusterState,
		clusterName:  cluster.Domain,
		clusterEnv:   clusterEnv,
		proxy:        proxy,
		leaderParams: leaderParams,
	}

	deployReq, err := newDeployAgentsRequest(ctx, req)
	if err != nil {
		return trace.Wrap(err)
	}

	err = rpc.DeployAgents(ctx, *deployReq)
	if err != nil {
		return trace.Wrap(err, "failed to deploy agents")
	}

	return nil
}

func verifyCluster(
	ctx context.Context,
	clusterState storage.ClusterState,
	proxy *teleclient.ProxyClient,
) (servers []rpc.DeployServer, err error) {
	var missing []string
	servers = make([]rpc.DeployServer, 0, len(servers))

	for _, server := range clusterState.Servers {
		deployServer, err := rpc.NewDeployServer(ctx, server, proxy)
		if err != nil && !trace.IsNotFound(err) {
			return nil, trace.Wrap(err)
		}
		if trace.IsNotFound(err) {
			missing = append(missing, server.Hostname)
		} else {
			servers = append(servers, *deployServer)
		}
	}
	if len(missing) != 0 {
		return nil, trace.NotFound(
			"Teleport is unavailable "+
				"on the following cluster nodes: %s. Please "+
				"make sure that the Teleport service is running "+
				"and try again.", strings.Join(missing, ", "))
	}

	return servers, nil
}

func upsertRPCCredentialsPackage(
	servers []rpc.DeployServer,
	packages pack.PackageService,
	clusterName string,
	packageTemplate loc.Locator) (secretsPackage *loc.Locator, err error) {
	hosts := make([]string, 0, len(servers))
	for _, server := range servers {
		hosts = append(hosts, strings.Split(server.NodeAddr, ":")[0])
	}

	archive, err := rpc.GenerateAgentCredentials(hosts, clusterName, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	secretsPackage, err = rpc.GenerateAgentCredentialsPackage(packages, packageTemplate, archive)
	if err != nil && !trace.IsAlreadyExists(err) {
		return nil, trace.Wrap(err)
	}
	return secretsPackage, nil
}

func deployAgents(ctx context.Context, env *localenv.LocalEnvironment, req deployAgentsRequest) (credentials.TransportCredentials, error) {
	deployReq, err := newDeployAgentsRequest(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = rpc.DeployAgents(ctx, *deployReq)
	if err != nil {
		return nil, trace.Wrap(err, "failed to deploy agents")
	}

	clientCreds, err := getClientCredentials(ctx, req.clusterEnv.ClusterPackages, deployReq.SecretsPackage)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return clientCreds, nil
}

func deployUpdateAgents(ctx context.Context, localEnv, updateEnv *localenv.LocalEnvironment, clusterEnv *localenv.ClusterEnvironment, cluster *ops.Site, manual bool) error {
	oldTeleport, err := isOldTeleport(cluster)
	if err != nil {
		return trace.Wrap(err)
	}

	if oldTeleport {
		return deployAgentsLegacy(localEnv, cluster, []string{constants.RpcAgentUpgradeFunction})
	}

	teleportClient, err := localEnv.TeleportClient(constants.Localhost)
	if err != nil {
		return trace.Wrap(err, "failed to create a teleport client")
	}

	proxy, err := teleportClient.ConnectToProxy(ctx)
	if err != nil {
		return trace.Wrap(err, "failed to connect to teleport proxy")
	}

	req := deployAgentsRequest{
		clusterState: cluster.ClusterState,
		clusterName:  cluster.Domain,
		clusterEnv:   clusterEnv,
		proxy:        proxy,
	}

	if !manual {
		req.leaderParams = []string{constants.RpcAgentUpgradeFunction}
		// attempt to schedule the master agent on this node but do not
		// treat the failure to do so as critical
		req.leader, err = findLocalServer(*cluster)
		if err != nil {
			log.Warnf("Failed to determine local node: %v.",
				trace.DebugReport(err))
		}
	}

	deployReq, err := newDeployAgentsRequest(ctx, req)
	if err != nil {
		return trace.Wrap(err)
	}

	err = rpc.DeployAgents(ctx, *deployReq)
	if err != nil {
		return trace.Wrap(err, "failed to deploy agents")
	}

	return nil
}

// newDeployAgentsRequest creates a new request to deploy agents on the local cluster
func newDeployAgentsRequest(ctx context.Context, req deployAgentsRequest) (*rpc.DeployAgentsRequest, error) {
	servers, err := verifyCluster(ctx, req.clusterState, req.proxy)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	gravityPackage := getGravityPackage()
	secretsPackageTemplate := loc.Locator{
		Repository: req.clusterName,
		Version:    gravityPackage.Version,
	}
	secretsPackage, err := upsertRPCCredentialsPackage(
		servers, req.clusterEnv.ClusterPackages, req.clusterName, secretsPackageTemplate)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &rpc.DeployAgentsRequest{
		Proxy:          req.proxy,
		ClusterState:   req.clusterState,
		Servers:        servers,
		SecretsPackage: *secretsPackage,
		GravityPackage: gravityPackage,
		FieldLogger:    logrus.WithField(trace.Component, "rpc:deploy"),
		LeaderParams:   req.leaderParams,
	}, nil
}

func getClientCredentials(ctx context.Context, packages pack.PackageService, secretsPackage loc.Locator) (credentials.TransportCredentials, error) {
	var r io.Reader
	ctx, cancel := defaults.WithTimeout(ctx)
	defer cancel()
	err := utils.RetryWithInterval(ctx, utils.NewUnlimitedExponentialBackOff(), func() (err error) {
		_, r, err = packages.ReadPackage(secretsPackage)
		if err != nil {
			if utils.IsPathError(err) {
				log.Debugf("Package %v has not been replicated yet, will retry.", secretsPackage)
				return trace.Wrap(err)
			}
			return &backoff.PermanentError{Err: err}
		}
		return nil
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsArchive, err := utils.ReadTLSArchive(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clientCreds, err := rpc.ClientCredentialsFromKeyPairs(
		*tlsArchive[pb.Client], *tlsArchive[pb.CA])
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return clientCreds, nil
}

func rpcAgentShutdown(env *localenv.LocalEnvironment) error {
	env.Println("Preparing to shutdown agents.")
	creds, err := fsm.GetClientCredentials()
	if err != nil {
		return trace.Wrap(err)
	}
	runner := fsm.NewAgentRunner(creds)
	err = update.ShutdownClusterAgents(context.TODO(), runner)
	return trace.Wrap(err)
}

func getGravityPackage() loc.Locator {
	ver := version.Get()
	return loc.Locator{
		Repository: defaults.SystemAccountOrg,
		Name:       constants.GravityPackage,
		Version:    strings.Split(ver.Version, "+")[0],
	}
}

type deployAgentsRequest struct {
	clusterEnv   *localenv.ClusterEnvironment
	clusterState storage.ClusterState
	clusterName  string
	proxy        *teleclient.ProxyClient
	leaderParams []string
	leader       *storage.Server
}
