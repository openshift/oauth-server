module github.com/openshift/oauth-server

go 1.12

require (
	bitbucket.org/ww/goautoneg v0.0.0-20120707110453-75cd24fc2f2c // indirect
	github.com/RangelReale/osin v0.0.0
	github.com/RangelReale/osincli v0.0.0
	github.com/certifi/gocertifi v0.0.0-20180905225744-ee1a9a0726d2 // indirect
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/getsentry/raven-go v0.0.0-20171206001108-32a13797442c // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/gophercloud/gophercloud v0.1.0
	github.com/gorilla/context v0.0.0-20190627024605-8559d4a6b87e // indirect
	github.com/gorilla/securecookie v0.0.0-20190707033817-86450627d8e6 // indirect
	github.com/gorilla/sessions v0.0.0-20171008214740-a3acf13e802c
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.10.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/natefinch/lumberjack v2.0.0+incompatible // indirect
	github.com/onsi/ginkgo v1.9.0 // indirect
	github.com/onsi/gomega v1.7.0 // indirect
	github.com/openshift/api v3.9.1-0.20190923092516-169848dd8137+incompatible
	github.com/openshift/client-go v0.0.0-20190923092832-6afefc9bb372
	github.com/openshift/library-go v0.0.0-20190923093227-76b67dd70a86
	github.com/pkg/profile v1.3.0 // indirect
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/common v0.2.0 // indirect
	github.com/soheilhy/cmux v0.1.4 // indirect
	github.com/spf13/cobra v0.0.0-20180319062004-c439c4fa0937
	github.com/spf13/pflag v1.0.3
	github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5 // indirect
	github.com/ugorji/go v1.1.7 // indirect
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
	go.etcd.io/bbolt v1.3.3 // indirect
	go.uber.org/atomic v1.4.0 // indirect
	go.uber.org/multierr v1.1.0 // indirect
	go.uber.org/zap v1.10.0 // indirect
	golang.org/x/crypto v0.0.0-20190611184440-5c40567a22f8
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v2 v2.5.1
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0 // indirect
	k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/apiserver v0.0.0-20190918160949-bfa5e2e684ad
	k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
	k8s.io/component-base v0.0.0-20190918160511-547f6c5d7090
	k8s.io/klog v0.4.0
)

replace (
	github.com/RangelReale/osin => github.com/openshift/osin v1.0.1-0.20180202150137-2dc1b4316769
	github.com/RangelReale/osincli => github.com/openshift/osincli v0.0.0-20190724130521-fababb0555f2
)
