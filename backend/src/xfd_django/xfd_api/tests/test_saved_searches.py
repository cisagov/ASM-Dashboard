# Standard Python Libraries
from datetime import datetime
import secrets

# Third-Party Libraries
from fastapi.testclient import TestClient
import pytest
from xfd_api.models import User, SavedSearch, UserType
from xfd_django.asgi import app
from xfd_api.auth import create_jwt_token

client = TestClient(app)

@pytest.mark.django_db
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
        json={
            "name": name,
            "count": 3,
            "sortDirection": "",
            "sortField": "",
            "searchTerm": "",
            "searchPath": "",
            "filters": []
        },
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == name
    assert data["createdById"] == str(user.id)

@pytest.mark.django_db
def test_update_saved_search_by_global_admin_fails():
    body = {
        "name": f"test-{secrets.token_hex(4)}",
        "count": 3,
        "sortDirection": "",
        "sortField": "",
        "searchTerm": "",
        "searchPath": "",
        "filters": []
    }
    search = SavedSearch.objects.create(**body)
    body["name"] = f"test-{secrets.token_hex(4)}"
    body["searchTerm"] = "123"
    response = client.put(
        f"/saved-searches/{search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(UserType.GLOBAL_ADMIN)},
    )
    assert response.status_code == 404

@pytest.mark.django_db
def test_update_saved_search_by_standard_user_with_access():
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
        "filters": []
    }
    search = SavedSearch.objects.create(**body, createdById=user)
    body["name"] = f"test-{secrets.token_hex(4)}"
    body["searchTerm"] = "123"
    response = client.put(
        f"/saved-searches/{search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == body["name"]
    assert data["searchTerm"] == body["searchTerm"]

@pytest.mark.django_db
def test_update_saved_search_by_standard_user_without_access_fails():
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
        "createdById": user
    }
    search = SavedSearch.objects.create(**body)
    response = client.put(
        f"/saved-searches/{search.id}",
        json=body,
        headers={"Authorization": "Bearer " + create_jwt_token(user1)},
    )
    assert response.status_code == 404

@pytest.mark.django_db
def test_delete_saved_search_by_global_admin_fails():
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[]
    )
    response = client.delete(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(UserType.GLOBAL_ADMIN)},
    )
    assert response.status_code == 404

@pytest.mark.django_db
def test_delete_saved_search_by_user_with_access():
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
        createdById=user
    )
    response = client.delete(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"

@pytest.mark.django_db
def test_delete_saved_search_by_user_without_access_fails():
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
        createdById=user
    )
    response = client.delete(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user1)},
    )
    assert response.status_code == 404

@pytest.mark.django_db
def test_list_saved_searches_by_global_view_returns_none():
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[]
    )
    response = client.get(
        "/saved-searches",
        headers={"Authorization": "Bearer " + create_jwt_token(UserType.GLOBAL_VIEW)},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 0

@pytest.mark.django_db
def test_list_saved_searches_by_user_only_gets_their_search():
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
        createdById=user
    )
    search2 = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[],
        createdById=user1
    )
    response = client.get(
        "/saved-searches",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["result"][0]["id"] == str(search.id)

@pytest.mark.django_db
def test_get_saved_search_by_global_view_fails():
    search = SavedSearch.objects.create(
        name=f"test-{secrets.token_hex(4)}",
        count=3,
        sortDirection="",
        sortField="",
        searchTerm="",
        searchPath="",
        filters=[]
    )
    response = client.get(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(UserType.GLOBAL_VIEW)},
    )
    assert response.status_code == 404

@pytest.mark.django_db
def test_get_saved_search_by_user_passes():
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
        createdById=user
    )
    response = client.get(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 200
    assert response.json()["name"] == search.name

@pytest.mark.django_db
def test_get_saved_search_by_different_user_fails():
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
        createdById=user1
    )
    response = client.get(
        f"/saved-searches/{search.id}",
        headers={"Authorization": "Bearer " + create_jwt_token(user)},
    )
    assert response.status_code == 404
    assert response.json() == {}