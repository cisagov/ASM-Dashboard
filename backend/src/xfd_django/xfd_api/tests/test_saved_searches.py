# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.auth import create_jwt_token
from xfd_api.models import SavedSearch, User, UserType
from xfd_django.asgi import app

client = TestClient(app)


@pytest.mark.django_db(transaction=True)
def test_create_saved_search_by_user():
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    name = f"test-{secrets.token_hex(4)}"
    response = client.post(
        "/saved-searches/",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
        json={
            "name": name,
            "count": 3,
            "sortDirection": "",
            "sortField": "",
            "searchTerm": "",
            "searchPath": "",
            "filters": [],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == name
    assert data["createdById"] == str(user.id)
    search = SavedSearch.objects.get(id=data["id"])
    search.delete()
    user.delete()


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_global_admin_fails():
    # pass
    global_admin_user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    standard_user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    body = {
        "name": f"test-{secrets.token_hex(4)}",
        "count": 3,
        "sortDirection": "",
        "sortField": "",
        "searchTerm": "",
        "searchPath": "",
        "filters": [],
        "updatedAt": datetime.now(),  # Include updatedAt field
    }
    search = SavedSearch.objects.create(**body, createdById=standard_user)
    body["name"] = f"test-{secrets.token_hex(4)}"
    body["searchTerm"] = "123"
    body["updatedAt"] = datetime.now().isoformat()  # Update the timestamp

    response = client.put(
        f"/saved-searches/{search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(global_admin_user)},
    )
    assert response.status_code == 404

    # Cleanup
    global_admin_user.delete()
    standard_user.delete()
    search.delete()


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_global_view_fails():
    """Ensure that a global view user cannot update a saved search."""
    # Create a standard user and a saved search
    # pass
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    body = {
        "name": f"test-{secrets.token_hex(4)}",
        "count": 3,
        "sortDirection": "",
        "sortField": "",
        "searchTerm": "",
        "searchPath": "",
        "filters": [],
        "updatedAt": datetime.now(),  # Include updatedAt field
    }
    saved_search = SavedSearch.objects.create(**body, createdById=user)

    # Create a global view user
    global_view_user = User.objects.create(
        firstName="Global",
        lastName="Viewer",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Attempt to update the saved search with the global view user
    body["name"] = f"test-{secrets.token_hex(4)}"
    body["searchTerm"] = "123"
    body["updatedAt"] = datetime.now().isoformat()  # Update the timestamp

    response = client.put(
        f"/saved-searches/{saved_search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(global_view_user)},
    )

    print(saved_search)
    print(response.json())

    # Assert that the response indicates failure (403 or 404)
    assert response.status_code == 404

    # Cleanup
    user.delete()
    global_view_user.delete()
    saved_search.delete()


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_standard_user_with_access():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    body = {
        "name": f"test-{secrets.token_hex(4)}",
        "count": 3,
        "sortDirection": "",
        "sortField": "",
        "searchTerm": "",
        "searchPath": "",
        "filters": [],
        "updatedAt": datetime.now(),  # Include updatedAt field
    }
    search = SavedSearch.objects.create(**body, createdById=user)
    body["name"] = f"test-{secrets.token_hex(4)}"
    body["searchTerm"] = "123"
    body["updatedAt"] = datetime.now().isoformat()  # Update the timestamp

    response = client.put(
        f"/saved-searches/{search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == body["name"]
    assert data["searchTerm"] == body["searchTerm"]

    # Cleanup
    search.delete()
    user.delete()


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_standard_user_without_access_fails():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user1 = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    body = {
        "name": f"test-{secrets.token_hex(4)}",
        "count": 3,
        "sortDirection": "",
        "sortField": "",
        "searchTerm": "",
        "searchPath": "",
        "filters": [],
        "updatedAt": str(datetime.now()),  # Include updatedAt field
    }
    search = SavedSearch.objects.create(**body, createdById=user)
    response = client.put(
        f"/saved-searches/{search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(user1)},
    )
    assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_global_admin_fails():
    # pass
    global_admin_user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_ADMIN,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    standard_user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=standard_user,
    )
    response = client.delete(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(global_admin_user)},
    )
    assert response.status_code == 404

    global_admin_user.delete()
    standard_user.delete()
    if search:
        search.delete()


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_global_view_fails():
    """Ensure that a global view user cannot delete a saved search."""
    # Create a standard user and a saved search
    # pass
    user = User.objects.create(
        firstName="Test",
        lastName="User",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    saved_search = SavedSearch.objects.create(
        name=f"test-search-{secrets.token_hex(4)}",
        count=5,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user,
    )

    # Create a global view user
    global_view_user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )

    # Attempt to delete the saved search with the global view user
    response = client.delete(
        f"/saved-searches/{saved_search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(global_view_user)},
    )

    # Assert that the response indicates failure (403 or 404)
    assert response.status_code == 404

    # Cleanup
    user.delete()
    global_view_user.delete()
    saved_search.delete()


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_user_with_access():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user,
    )
    response = client.delete(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )

    assert response.status_code == 200
    user.delete()
    if search:
        search.delete()


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_user_without_access_fails():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user1 = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user,
    )
    response = client.delete(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user1)},
    )
    assert response.status_code == 404
    user.delete()
    user1.delete()
    if search:
        search.delete()


@pytest.mark.django_db(transaction=True)
def test_list_saved_searches_by_global_view_returns_none():
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
    )
    response = client.get(
        "/saved-searches",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    assert len(response.json()) == 0
    search.delete()
    user.delete()


@pytest.mark.django_db(transaction=True)
def test_list_saved_searches_by_user_only_gets_their_search():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user1 = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user,
    )
    search2 = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user1,
    )
    response = client.get(
        "/saved-searches",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == str(search.id)
    search.delete()
    search2.delete()
    user.delete()
    user1.delete()


@pytest.mark.django_db(transaction=True)
def test_get_saved_search_by_global_view_fails():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.GLOBAL_VIEW,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
    )
    response = client.get(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 404
    search.delete()
    user.delete()


# This test is passing
@pytest.mark.django_db(transaction=True)
def test_get_saved_search_by_user_passes():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user,
    )
    response = client.get(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    assert response.json()["name"] == search.name
    search.delete()
    user.delete()


@pytest.mark.django_db(transaction=True)
def test_get_saved_search_by_different_user_fails():
    # pass
    user = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    user1 = User.objects.create(
        firstName="",
        lastName="",
        email=f"{secrets.token_hex(4)}@example.com",
        userType=UserType.STANDARD,
        createdAt=datetime.now(),
        updatedAt=datetime.now(),
    )
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user1,
    )
    response = client.get(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 404
    search.delete()
    user.delete()
    user1.delete()
