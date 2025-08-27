package main

import (
	"context"
	goflag "flag"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/component-base/cli"
	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"

	"github.com/openshift/library-go/pkg/serviceability"
	openshift_integrated_oauth_server "github.com/openshift/oauth-server/pkg/cmd/oauth-server"
	"github.com/openshift/oauth-server/pkg/version"
)

func main() {
	ctx := genericapiserver.SetupSignalContext()
	defer ctx.Done()

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()
	defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
	defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	command, err := NewOpenshiftIntegratedOAuthServerCommand(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
	os.Exit(cli.Run(command))
}

func NewOpenshiftIntegratedOAuthServerCommand(ctx context.Context) (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "oauth-server",
		Short: "Command for the OpenShift integrated OAuth server",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
			os.Exit(1)
		},
	}

	startOsin, err := openshift_integrated_oauth_server.NewOsinServerCommand(ctx, os.Stdout, os.Stderr)
	if err != nil {
		return nil, err
	}

	cmd.AddCommand(startOsin)

	return cmd, nil
}
