package groupmapper

import (
	"context"
	"fmt"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	userv1 "github.com/openshift/api/user/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	userinformer "github.com/openshift/client-go/user/informers/externalversions/user/v1"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"

	authapi "github.com/openshift/oauth-server/pkg/api"
)

const (
	groupGeneratedKey = "oauth.openshift.io/generated"
	groupSyncedKeyFmt = "oauth.openshift.io/idp.%s"
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
}

func NewUserGroupsMapper(delegate authapi.UserIdentityMapper, groupInformer userinformer.GroupInformer, groupsClient userclient.GroupInterface, groupsLister userlisterv1.GroupLister) *UserGroupsMapper {
	return &UserGroupsMapper{
		delegatedUserMapper: delegate,
		groupsClient:        groupsClient,
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

// processGroups synchronizes the user's group memberships with the identity provider.
// NOTE: This makes a direct API call to list all groups on every login to ensure
// correctness and avoid cache staleness issues (see OCPBUGS-63228).
func (m *UserGroupsMapper) processGroups(idpName, username string, providerGroups sets.String) error {
	ctx := context.Background()
	clusterGroupsList, err := m.groupsClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("could not list cluster groups: %v", err)
	}

	clusterGroups := map[string]*userv1.Group{}
	for _, g := range clusterGroupsList.Items {
		clusterGroups[g.Name] = &g
	}

	userGroupsForIDP := make([]*userv1.Group, 0)
	for _, g := range clusterGroupsList.Items {
		if g.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] == "synced" && slices.Contains(g.Users, username) {
			userGroupsForIDP = append(userGroupsForIDP, &g)
		}
	}

	removeGroups, addGroups := groupsDiff(userGroupsForIDP, providerGroups)
	for _, g := range removeGroups {
		if err := m.removeUserFromGroup(ctx, idpName, username, clusterGroups[g]); err != nil {
			return err
		}
	}

	for _, g := range addGroups {
		if err := m.addUserToGroup(ctx, idpName, username, g, clusterGroups[g]); err != nil {
			return err
		}
	}

	return nil
}

func (m *UserGroupsMapper) removeUserFromGroup(ctx context.Context, idpName, username string, group *userv1.Group) error {
	if group == nil || len(group.Users) == 0 {
		return nil
	}

	if len(group.Users) == 1 && group.Users[0] == username && group.Annotations[groupGeneratedKey] == "true" {
		return m.groupsClient.Delete(ctx, group.Name, metav1.DeleteOptions{})
	}

	// don't perform any actions on the group if it hasn't been synced for this IdP
	if group.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] != "synced" {
		return nil
	}

	// find the user and remove it from the slice
	userIdx := -1
	for i, groupUser := range group.Users {
		if groupUser == username {
			userIdx = i
			break
		}
	}

	var newUsers []string
	switch userIdx {
	case -1:
		return nil
	case 0:
		newUsers = group.Users[1:]
	default:
		newUsers = append(group.Users[0:userIdx], group.Users[userIdx+1:]...)
	}

	updatedGroupCopy := group.DeepCopy()
	updatedGroupCopy.Users = newUsers

	_, err := m.groupsClient.Update(ctx, updatedGroupCopy, metav1.UpdateOptions{})
	return err
}

func (m *UserGroupsMapper) addUserToGroup(ctx context.Context, idpName, username, groupName string, updatedGroup *userv1.Group) error {
	if updatedGroup == nil {
		_, err := m.groupsClient.Create(ctx,
			&userv1.Group{
				ObjectMeta: metav1.ObjectMeta{
					Name: groupName,
					Annotations: map[string]string{
						fmt.Sprintf(groupSyncedKeyFmt, idpName): "synced",
						groupGeneratedKey:                       "true",
					},
				},
				Users: []string{username},
			},
			metav1.CreateOptions{},
		)
		return err
	}

	if updatedGroup.Annotations == nil {
		updatedGroup.Annotations = map[string]string{}
	}

	var onlyAddAnnotation bool
	for _, u := range updatedGroup.Users {
		if u == username {
			if updatedGroup.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] != "synced" {
				onlyAddAnnotation = true
				break
			}
			return nil
		}
	}

	updatedGroupCopy := updatedGroup.DeepCopy()
	if !onlyAddAnnotation {
		updatedGroupCopy.Users = append(updatedGroup.Users, username)
	}
	updatedGroupCopy.Annotations[fmt.Sprintf(groupSyncedKeyFmt, idpName)] = "synced"

	_, err := m.groupsClient.Update(ctx, updatedGroupCopy, metav1.UpdateOptions{})
	return err
}

func groupsDiff(existing []*userv1.Group, required sets.String) (toRemove, toAdd []string) {
	existingNames := sets.NewString()
	for _, g := range existing {
		existingNames.Insert(g.Name)
	}

	return existingNames.Difference(required).UnsortedList(), required.Difference(existingNames).UnsortedList()
}
