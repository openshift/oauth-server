package groupmapper

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	userv1 "github.com/openshift/api/user/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	userinformer "github.com/openshift/client-go/user/informers/externalversions/user/v1"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"
	usercache "github.com/openshift/library-go/pkg/oauth/usercache"

	authapi "github.com/openshift/oauth-server/pkg/api"
)

const (
	groupGeneratedKey = "oauth.openshift.io/generated"
	groupSyncedKeyFmt = "oauth.openshift.io/idp.%s"

	// Kubernetes annotation name parts are limited to 63 characters. The
	// "idp." prefix of groupSyncedKeyFmt consumes 4 of those.
	maxIDPAnnotationNameLen = 63 - len("idp.")
)

var _ authapi.UserIdentityMapper = &UserGroupsMapper{}

var _ kuser.Info = &UserInfoGroupsWrapper{}

// UserInfoGroupsWrapper wraps a UserInfo object in order to add extra groups
// retrieved from the identity providers
type UserInfoGroupsWrapper struct {
	userInfo         kuser.Info
	additionalGroups sets.String
}

func (w *UserInfoGroupsWrapper) GetName() string {
	return w.userInfo.GetName()
}

func (w *UserInfoGroupsWrapper) GetUID() string {
	return w.userInfo.GetUID()
}

func (w *UserInfoGroupsWrapper) GetExtra() map[string][]string {
	return w.userInfo.GetExtra()
}

func (w *UserInfoGroupsWrapper) GetGroups() []string {
	groups := w.additionalGroups.Union(sets.NewString(w.userInfo.GetGroups()...))
	return groups.List()
}

// UserGroupsMapper wraps a UserIdentityMapper with a struct that's capable to
// create the groups for a given user based on the provided UserIdentityInfo
type UserGroupsMapper struct {
	delegatedUserMapper authapi.UserIdentityMapper
	groupsClient        userclient.GroupInterface
	groupsLister        userlisterv1.GroupLister
	groupsCache         *usercache.GroupCache
	groupsSynced        func() bool
}

func NewUserGroupsMapper(delegate authapi.UserIdentityMapper, groupInformer userinformer.GroupInformer, groupsClient userclient.GroupInterface, groupsLister userlisterv1.GroupLister) *UserGroupsMapper {
	return &UserGroupsMapper{
		delegatedUserMapper: delegate,
		groupsClient:        groupsClient,
		groupsLister:        groupsLister,
		groupsCache:         usercache.NewGroupCache(groupInformer),
		groupsSynced:        groupInformer.Informer().HasSynced,
	}
}

func (m *UserGroupsMapper) UserFor(identityInfo authapi.UserIdentityInfo) (kuser.Info, error) {
	userInfo, err := m.delegatedUserMapper.UserFor(identityInfo)
	if err != nil {
		return userInfo, err
	}

	identityGroups := sets.NewString(identityInfo.GetProviderGroups()...)
	if err := m.processGroups(identityInfo.GetProviderName(), identityInfo.GetProviderPreferredUserName(), identityGroups); err != nil {
		return nil, err
	}

	return &UserInfoGroupsWrapper{
		userInfo:         userInfo,
		additionalGroups: identityGroups,
	}, nil
}

func (m *UserGroupsMapper) processGroups(idpName, username string, groups sets.String) error {
	err := wait.PollImmediate(1*time.Second, 5*time.Second, func() (bool, error) {
		return m.groupsSynced(), nil
	})
	if err != nil {
		return err
	}

	cachedGroups, err := m.groupsCache.GroupsFor(username)
	if err != nil {
		return err
	}

	removeGroups, addGroups := groupsDiff(cachedGroups, groups)
	for _, g := range removeGroups {
		if err := m.removeUserFromGroup(idpName, username, g); err != nil {
			return err
		}
	}

	for _, g := range addGroups {
		if err := m.addUserToGroup(idpName, username, g); err != nil {
			return err
		}
	}

	return nil
}

func (m *UserGroupsMapper) removeUserFromGroup(idpName, username, group string) error {
	updatedGroup, err := m.groupsLister.Get(group)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if len(updatedGroup.Users) == 0 {
		return nil
	}

	if len(updatedGroup.Users) == 1 && updatedGroup.Users[0] == username && updatedGroup.Annotations[groupGeneratedKey] == "true" {
		return m.groupsClient.Delete(context.TODO(), group, metav1.DeleteOptions{})
	}

	// don't perform any actions on the group if it hasn't been synced for this IdP
	if updatedGroup.Annotations[idpAnnotationKey(idpName)] != "synced" {
		return nil
	}

	// find the user and remove it from the slice
	userIdx := slices.Index(updatedGroup.Users, username)
	if userIdx == -1 {
		return nil
	}

	newUsers := make([]string, 0, len(updatedGroup.Users)-1)
	newUsers = append(newUsers, updatedGroup.Users[:userIdx]...)
	newUsers = append(newUsers, updatedGroup.Users[userIdx+1:]...)

	updatedGroupCopy := updatedGroup.DeepCopy()
	updatedGroupCopy.Users = newUsers

	_, err = m.groupsClient.Update(context.TODO(), updatedGroupCopy, metav1.UpdateOptions{})
	return err
}

func (m *UserGroupsMapper) addUserToGroup(idpName, username, group string) error {
	updatedGroup, err := m.groupsLister.Get(group)
	if errors.IsNotFound(err) {
		_, err = m.groupsClient.Create(context.TODO(),
			&userv1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name: group,
					Annotations: map[string]string{
						idpAnnotationKey(idpName): "synced",
						groupGeneratedKey:         "true",
					},
				},
				Users: []string{username},
			},
			metav1.CreateOptions{},
		)
		return err
	}
	if err != nil {
		return err
	}

	if updatedGroup.Annotations == nil {
		updatedGroup.Annotations = map[string]string{}
	}

	var onlyAddAnnotation bool
	for _, u := range updatedGroup.Users {
		if u == username {
			if updatedGroup.Annotations[idpAnnotationKey(idpName)] != "synced" {
				onlyAddAnnotation = true
				break
			}
			return nil
		}
	}

	updatedGroupCopy := updatedGroup.DeepCopy()
	if !onlyAddAnnotation {
		updatedGroupCopy.Users = append(updatedGroupCopy.Users, username)
	}
	updatedGroupCopy.Annotations[idpAnnotationKey(idpName)] = "synced"

	_, err = m.groupsClient.Update(context.TODO(), updatedGroupCopy, metav1.UpdateOptions{})
	return err
}

func groupsDiff(existing []*userv1.Group, required sets.String) (toRemove, toAdd []string) {
	existingNames := sets.NewString()
	for _, g := range existing {
		existingNames.Insert(g.Name)
	}

	return existingNames.Difference(required).UnsortedList(), required.Difference(existingNames).UnsortedList()
}

// idpAnnotationKey returns the Group annotation used to record that a group
// was synchronized from the named identity provider.
//
// The IdP name is sanitized because Kubernetes annotation keys cannot contain
// spaces or other characters that are otherwise legal in identity provider
// names. Login paths already tolerate those names (OCPBUGS-42772, OCPBUGS-44099);
// group sync must as well (OCPBUGS-56908).
func idpAnnotationKey(idpName string) string {
	return fmt.Sprintf(groupSyncedKeyFmt, sanitizeIDPNameForAnnotation(idpName))
}

// sanitizeIDPNameForAnnotation rewrites an identity provider name so it is
// valid as the name part of a Kubernetes annotation key (alphanumeric, '-',
// '_', '.', must start and end with alphanumeric). Invalid characters are
// replaced with '-' rather than stripped so distinct names stay distinct
// ("AIF - Keycloak" vs "AIF-Keycloak").
func sanitizeIDPNameForAnnotation(name string) string {
	if name == "" {
		return "unknown"
	}

	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if isAnnotationNameRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}

	sanitized := strings.Trim(b.String(), "-_.")
	if sanitized == "" {
		return "unknown"
	}
	if len(sanitized) > maxIDPAnnotationNameLen {
		sanitized = strings.TrimRight(sanitized[:maxIDPAnnotationNameLen], "-_.")
		if sanitized == "" {
			return "unknown"
		}
	}
	return sanitized
}

func isAnnotationNameRune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-' || r == '_' || r == '.':
		return true
	default:
		return false
	}
}
