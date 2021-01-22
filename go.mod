module github.com/openshift/oauth-server

go 1.14

require (
	github.com/RangelReale/osin v0.0.0
	github.com/RangelReale/osincli v0.0.0
	github.com/davecgh/go-spew v1.1.1
	github.com/gophercloud/gophercloud v0.1.0
	github.com/gorilla/context v0.0.0-20190627024605-8559d4a6b87e // indirect
	github.com/gorilla/securecookie v0.0.0-20190707033817-86450627d8e6 // indirect
	github.com/gorilla/sessions v0.0.0-20171008214740-a3acf13e802c
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.10.0 // indirect
	github.com/openshift/api v0.0.0-20200827090112-c05698d102cf
	github.com/openshift/build-machinery-go v0.0.0-20200819073603-48aa266c95f7
	github.com/openshift/client-go v0.0.0-20200827190008-3062137373b5
	github.com/openshift/library-go v0.0.0-20201123124259-522c6f69be23
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6
	gopkg.in/ldap.v2 v2.5.1
	k8s.io/api v0.19.0
	k8s.io/apimachinery v0.19.0
	k8s.io/apiserver v0.19.0
	k8s.io/client-go v0.19.0
	k8s.io/component-base v0.19.0
	k8s.io/klog/v2 v2.3.0
)

replace (
	github.com/RangelReale/osin => github.com/openshift/osin v1.0.1-0.20180202150137-2dc1b4316769
	github.com/RangelReale/osincli => github.com/openshift/osincli v0.0.0-20160924135400-fababb0555f2
	k8s.io/apiserver => github.com/openshift/kubernetes-apiserver v0.0.0-20201207110950-476028df0fd8 // points to openshift-apiserver-4.6-kubernetes-1.19.0
	k8s.io/client-go => github.com/openshift/kubernetes-client-go v0.0.0-20201207133257-210b92e25f6a
)
