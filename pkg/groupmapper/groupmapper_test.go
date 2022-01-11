package groupmapper

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/cache"

	userv1 "github.com/openshift/api/user/v1"
	fakeuserclient "github.com/openshift/client-go/user/clientset/versioned/fake"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"
	usercache "github.com/openshift/library-go/pkg/oauth/usercache"

	authapi "github.com/openshift/oauth-server/pkg/api"
)

const testIDPName = "test-idp"

type mockUserMapper struct {
	userInfo kuser.DefaultInfo
}

func (m *mockUserMapper) UserFor(identityInfo authapi.UserIdentityInfo) (kuser.Info, error) {
	return &m.userInfo, nil
}

func TestUserGroupsMapper_UserFor(t *testing.T) {
	systemGroups := []string{"system:one", "system:two"}

	tests := []struct {
		name          string
		username      string
		idpGroups     []string
		want          kuser.Info
		wantErr       bool
		deletedGroups []string
	}{
		{
			name:          "no idp groups",
			username:      "user1",
			want:          &UserInfoGroupsWrapper{userInfo: &kuser.DefaultInfo{Name: "user1", UID: "tehUserUID", Groups: systemGroups}},
			deletedGroups: []string{"group_only1", "group_only1_too"},
		},
		{
			name:          "create a single group",
			username:      "user1",
			idpGroups:     []string{"group1_unique"},
			want:          &UserInfoGroupsWrapper{userInfo: &kuser.DefaultInfo{Name: "user1", UID: "tehUserUID", Groups: append(systemGroups, "group1_unique")}},
			deletedGroups: []string{"group_only1", "group_only1_too"},
		},
		{
			name:      "create multiple groups, be added to some, stay in others",
			username:  "user1",
			idpGroups: []string{"group1_unique", "group2_unique", "group1", "group13", "group2", "group3", "group_only1"},
			want: &UserInfoGroupsWrapper{userInfo: &kuser.DefaultInfo{
				Name:   "user1",
				UID:    "tehUserUID",
				Groups: append(systemGroups, "group1_unique", "group2_unique", "group1", "group13", "group2", "group3", "group_only1"),
			}},
			deletedGroups: []string{"group_only1_too"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			groupObjs := []runtime.Object{}
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for _, g := range basicGroups {
				groupObjs = append(groupObjs, g)
				require.NoError(t, indexer.Add(g))
			}
			fakeGroupsClient := fakeuserclient.NewSimpleClientset(groupObjs...)

			userInformer := userinformer.NewSharedInformerFactory(fakeGroupsClient, 5*time.Second)
			userInformer.User().V1().Groups().Informer().AddIndexers(cache.Indexers{
				usercache.ByUserIndexName: usercache.ByUserIndexKeys,
			})
			testCtx, cancelCtx := context.WithCancel(context.Background())
			go userInformer.Start(testCtx.Done())
			defer cancelCtx()

			m := &UserGroupsMapper{
				delegatedUserMapper: &mockUserMapper{userInfo: kuser.DefaultInfo{Name: tt.username, UID: "tehUserUID", Groups: []string{"system:one", "system:two"}}},
				groupsClient:        fakeGroupsClient.UserV1().Groups(),
				groupsLister:        userlisterv1.NewGroupLister(indexer),
				groupsCache:         usercache.NewGroupCache(userInformer.User().V1().Groups()),
				groupsSynced:        userInformer.User().V1().Groups().Informer().HasSynced,
			}

			identityInfo := &authapi.DefaultUserIdentityInfo{ProviderName: testIDPName, ProviderUserName: tt.username, ProviderGroups: tt.idpGroups}
			got, err := m.UserFor(identityInfo)
			if (err != nil) != tt.wantErr {
				t.Errorf("UserGroupsMapper.UserFor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.want.GetUID() != got.GetUID() ||
				tt.want.GetName() != got.GetName() ||
				!reflect.DeepEqual(tt.want.GetGroups(), got.GetGroups()) ||
				!reflect.DeepEqual(tt.want.GetExtra(), got.GetExtra()) {
				t.Errorf("UserGroupsMapper.UserFor() = %v, want %v", got, tt.want)
			}

			userPresent := func(u string, users []string) bool {
				for _, user := range users {
					if user == u {
						return true
					}
				}
				return false
			}

			// delete the groups from `userGroups` and eventually check that the set is empty -> user appears in all expected groups
			userGroups := sets.NewString(tt.idpGroups...)
			groups, err := fakeGroupsClient.UserV1().Groups().List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			for _, g := range groups.Items {
				assertion := require.False
				if userGroups.Has(g.Name) {
					assertion = require.True
				}
				assertion(t, userPresent(tt.username, g.Users))
				userGroups.Delete(g.Name)
			}
			require.True(t, userGroups.Len() == 0)

			for _, g := range tt.deletedGroups {
				_, err := fakeGroupsClient.UserV1().Groups().Get(context.Background(), g, metav1.GetOptions{})
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(err), "expected NotFound error, got %v", err)
			}
		})
	}
}

func TestUserGroupsMapper_removeUserFromGroup(t *testing.T) {
	const testGroupName = "test-group"

	tests := []struct {
		name          string
		username      string
		group         *userv1.Group
		expectedGroup *userv1.Group
		expectEvent   bool
		wantErr       bool
		wantDeletion  bool
	}{
		{
			name:          "nonexistent group",
			username:      "user1",
			group:         nil,
			expectedGroup: nil,
		},
		{
			name:          "no users in group",
			username:      "user1",
			group:         createGroupWithUsers(testGroupName),
			expectedGroup: createGroupWithUsers(testGroupName),
		},
		{
			name:          "user not in target group",
			username:      "user1",
			group:         createGroupWithUsers(testGroupName, "user2", "user3", "user4"),
			expectedGroup: createGroupWithUsers(testGroupName, "user2", "user3", "user4"),
		},
		{
			name:          "first user gets removed from the group",
			username:      "user1",
			group:         createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"),
			expectedGroup: createGroupWithUsers(testGroupName, "user2", "user3", "user4"),
			expectEvent:   true,
		},
		{
			name:          "mid user gets removed from the group",
			username:      "user2",
			group:         createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"),
			expectedGroup: createGroupWithUsers(testGroupName, "user1", "user3", "user4"),
			expectEvent:   true,
		},
		{
			name:          "last user gets removed from the group",
			username:      "user4",
			group:         createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"),
			expectedGroup: createGroupWithUsers(testGroupName, "user1", "user2", "user3"),
			expectEvent:   true,
		},
		{
			name:          "last user on group w/o generated annotation -> empty users",
			username:      "user1",
			group:         removeGeneratedKeyFromGroup(createGroupWithUsers(testGroupName, "user1")),
			expectedGroup: removeGeneratedKeyFromGroup(createGroupWithUsers(testGroupName)),
			expectEvent:   true,
		},
		{
			name:          "last user on group -> delete group",
			username:      "user1",
			group:         createGroupWithUsers(testGroupName, "user1"),
			expectedGroup: createGroupWithUsers(testGroupName, "user1"), // this is the obj being deleted
			wantDeletion:  true,
			expectEvent:   true,
		},
		{
			name:          "user on group w/o synced annotation -> do nothing",
			username:      "user2",
			group:         removeSyncedKeyFromGroup(createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"), testIDPName),
			expectedGroup: removeSyncedKeyFromGroup(createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"), testIDPName),
			expectEvent:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			groups := []runtime.Object{}
			if tt.group != nil {
				groups = append(groups, tt.group)
				require.NoError(t, indexer.Add(tt.group))
			}
			fakeUserClient := fakeuserclient.NewSimpleClientset(groups...)
			testCtx := context.Background()
			groupWatcher, err := fakeUserClient.UserV1().Groups().Watch(testCtx, metav1.ListOptions{})
			require.NoError(t, err)
			defer groupWatcher.Stop()

			m := &UserGroupsMapper{
				groupsLister: userlisterv1.NewGroupLister(indexer),
				groupsClient: fakeUserClient.UserV1().Groups(),
			}

			finished, failed := make(chan bool), make(chan string)
			timedCtx, timedCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)

			expectedEventType := watch.Modified
			if tt.wantDeletion {
				expectedEventType = watch.Deleted
			}
			go watchForGroupEvents(groupWatcher, tt.expectedGroup, tt.expectEvent, expectedEventType, failed, finished, timedCtx)

			go func() {
				if err := m.removeUserFromGroup(testIDPName, tt.username, testGroupName); (err != nil) != tt.wantErr {
					t.Errorf("UserGroupsMapper.removeUserFromGroup() error = %v, wantErr %v", err, tt.wantErr)
				}

				// give the watch some time
				time.Sleep(1 * time.Second)
				timedCtxCancel()
			}()

			select {
			case <-finished:
			case errMsg := <-failed:
				t.Fatal(errMsg)
			}

		})
	}
}

func TestUserGroupsMapper_addUserToGroup(t *testing.T) {
	const testGroupName = "test-group"

	tests := []struct {
		name          string
		username      string
		group         *userv1.Group
		expectedGroup *userv1.Group
		expectEvent   bool
		wantErr       bool
	}{
		{
			name:          "nonexistent group",
			username:      "user1",
			group:         nil,
			expectedGroup: createGroupWithUsers(testGroupName, "user1"),
			expectEvent:   true,
		},
		{
			name:          "group with no annotations yet - user missng",
			username:      "user2",
			group:         removeGroupAnnotations(createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4")),
			expectedGroup: removeGeneratedKeyFromGroup(createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4")),
			expectEvent:   true,
		},
		{
			name:          "group with no annotations yet - user present",
			username:      "user2",
			group:         removeGroupAnnotations(createGroupWithUsers(testGroupName, "user1", "user3", "user4")),
			expectedGroup: removeGeneratedKeyFromGroup(createGroupWithUsers(testGroupName, "user1", "user3", "user4", "user2")),
			expectEvent:   true,
		},
		{
			name:          "user already in group",
			username:      "user3",
			group:         createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"),
			expectedGroup: createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"),
		},
		{
			name:          "user in group w/o the synced annotation - add the annotation",
			username:      "user2",
			group:         removeSyncedKeyFromGroup(createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"), testIDPName),
			expectedGroup: createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4"),
			expectEvent:   true,
		},
		{
			name:          "user missing in the group",
			username:      "user99",
			group:         createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4", "user5", "user6"),
			expectedGroup: createGroupWithUsers(testGroupName, "user1", "user2", "user3", "user4", "user5", "user6", "user99"),
			expectEvent:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			groups := []runtime.Object{}
			if tt.group != nil {
				groups = append(groups, tt.group)
				require.NoError(t, indexer.Add(tt.group))
			}
			fakeUserClient := fakeuserclient.NewSimpleClientset(groups...)
			testCtx := context.Background()
			groupWatcher, err := fakeUserClient.UserV1().Groups().Watch(testCtx, metav1.ListOptions{})
			require.NoError(t, err)
			defer groupWatcher.Stop()

			m := &UserGroupsMapper{
				groupsLister: userlisterv1.NewGroupLister(indexer),
				groupsClient: fakeUserClient.UserV1().Groups(),
			}

			finished, failed := make(chan bool), make(chan string)
			timedCtx, timedCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)

			expectedEventType := watch.Modified
			if tt.group == nil && tt.expectedGroup != nil {
				expectedEventType = watch.Added
			}
			go watchForGroupEvents(groupWatcher, tt.expectedGroup, tt.expectEvent, expectedEventType, failed, finished, timedCtx)

			go func() {
				if err := m.addUserToGroup(testIDPName, tt.username, testGroupName); (err != nil) != tt.wantErr {
					t.Errorf("UserGroupsMapper.addUserToGroup() error = %v, wantErr %v", err, tt.wantErr)
				}

				// give the watch some time
				time.Sleep(1 * time.Second)
				timedCtxCancel()
			}()

			select {
			case <-finished:
			case errMsg := <-failed:
				t.Fatal(errMsg)
			}
		})
	}
}

func createGroupWithUsers(groupname string, users ...string) *userv1.Group {
	return &userv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name: groupname,
			Annotations: map[string]string{
				fmt.Sprintf(groupSyncedKeyFmt, testIDPName): "synced",
				groupGeneratedKey: "true",
			},
		},
		Users: users,
	}
}

func removeGeneratedKeyFromGroup(g *userv1.Group) *userv1.Group {
	delete(g.Annotations, groupGeneratedKey)
	return g
}

func removeSyncedKeyFromGroup(g *userv1.Group, idpName string) *userv1.Group {
	delete(g.Annotations, fmt.Sprintf(groupSyncedKeyFmt, idpName))
	return g
}

func removeGroupAnnotations(g *userv1.Group) *userv1.Group {
	g.Annotations = nil
	return g
}

func watchForGroupEvents(
	groupWatcher watch.Interface,
	expectedGroup *userv1.Group,
	expectEvent bool,
	expectedEventType watch.EventType,
	failChan chan<- string,
	finishChan chan<- bool,
	timeOutCtx context.Context,
) {
	userChan := groupWatcher.ResultChan()
	eventCount := 0
	for {
		select {
		case groupEvent := <-userChan:
			if !expectEvent {
				failChan <- fmt.Sprintf("unexpected event: %v", groupEvent)
				return
			}

			eventCount++
			group, ok := groupEvent.Object.(*userv1.Group)
			if !ok {
				failChan <- "the retrieved object was not a group"
				return
			}
			if !equality.Semantic.DeepEqual(expectedGroup, group) {
				failChan <- fmt.Sprintf("the expected group is different from the actual: %s", diff.ObjectDiff(expectedGroup, group))
				return
			}
			if expectedEventType != groupEvent.Type {
				failChan <- fmt.Sprintf("expected event of type %s, got %s", expectedEventType, groupEvent.Type)
				return
			}
		case <-timeOutCtx.Done():
			if eventCount == 0 && expectEvent {
				failChan <- "timed out"
			} else {
				finishChan <- true
			}
			return
		}
	}
}

var basicGroups = []*userv1.Group{
	createGroupWithUsers("group0", "user1", "user2", "user3", "user4", "user5", "user6"),
	createGroupWithUsers("group1", "user2", "user3", "user4", "user5", "user6"),
	createGroupWithUsers("group2", "user1", "user3", "user4", "user5", "user6"),
	createGroupWithUsers("group3", "user1", "user2", "user4", "user5", "user6"),
	createGroupWithUsers("group4", "user1", "user2", "user3", "user5", "user6"),
	createGroupWithUsers("group5", "user1", "user2", "user3", "user4", "user6"),
	createGroupWithUsers("group6", "user1", "user2", "user3", "user4", "user5"),
	createGroupWithUsers("group13", "user2", "user4", "user5", "user6"),
	createGroupWithUsers("group256", "user1", "user3", "user4"),
	createGroupWithUsers("group_only1", "user1"),     // for testing group removals
	createGroupWithUsers("group_only1_too", "user1"), // for testing group removals
}
