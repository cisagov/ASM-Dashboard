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


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_global_admin_fails():
    pass
    # user = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.GLOBAL_ADMIN,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # body = {
    #     "name": f"test-{secrets.token_hex(4)}",
    #     "count": 3,
    #     "sortDirection": "",
    #     "sortField": "",
    #     "searchTerm": "",
    #     "searchPath": "",
    #     "filters": [],
    # }
    # search = SavedSearch.objects.create(**body)
    # body["name"] = f"test-{secrets.token_hex(4)}"
    # body["searchTerm"] = "123"
    # response = client.put(
    #     f"/saved-searches/{search.id}",
    #     json=body,
    #     headers={"Authorization": "Bearer " + create_jwt_token(user)},
    # )
    # assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_standard_user_with_access():
    pass
    # user = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.STANDARD,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # body = {
    #     "name": f"test-{secrets.token_hex(4)}",
    #     "count": 3,
    #     "sortDirection": "",
    #     "sortField": "",
    #     "searchTerm": "",
    #     "searchPath": "",
    #     "filters": [],
    # }
    # search = SavedSearch.objects.create(**body, createdById=user)
    # body["name"] = f"test-{secrets.token_hex(4)}"
    # body["searchTerm"] = "123"
    # response = client.put(
    #     f"/saved-searches/{search.id}",
    #     json=body,
    #     headers={"Authorization": "Bearer " + create_jwt_token(user)},
    # )
    # assert response.status_code == 200
    # data = response.json()
    # assert data["name"] == body["name"]
    # assert data["searchTerm"] == body["searchTerm"]


@pytest.mark.django_db(transaction=True)
def test_update_saved_search_by_standard_user_without_access_fails():
    pass
    # user = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.STANDARD,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # user1 = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.STANDARD,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # body = {
    #     "name": f"test-{secrets.token_hex(4)}",
    #     "count": 3,
    #     "sortDirection": "",
    #     "sortField": "",
    #     "searchTerm": "",
    #     "searchPath": "",
    #     "filters": [],
    #     "createdById": user,
    # }
    # search = SavedSearch.objects.create(**body)
    # response = client.put(
    #     f"/saved-searches/{search.id}",
    #     json=body,
    #     headers={"Authorization": "Bearer " + create_jwt_token(user1)},
    # )
    # assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_global_admin_fails():
    pass
    # search = SavedSearch.objects.create(
    #     name=f"test-{secrets.token_hex(4)}",
    #     count=3,
    #     sortDirection="",
    #     sortField="",
    #     searchTerm="",
    #     searchPath="",
    #     filters=[],
    # )
    # response = client.delete(
    #     f"/saved-searches/{search.id}",
    #     headers={"Authorization": "Bearer " + create_jwt_token(UserType.GLOBAL_ADMIN)},
    # )
    # assert response.status_code == 404


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_user_with_access():
    pass
    # user = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.STANDARD,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # search = SavedSearch.objects.create(
    #     name=f"test-{secrets.token_hex(4)}",
    #     count=3,
    #     sortDirection="",
    #     sortField="",
    #     searchTerm="",
    #     searchPath="",
    #     filters=[],
    #     createdById=user,
    # )
    # response = client.delete(
    #     f"/saved-searches/{search.id}",
    #     headers={"Authorization": "Bearer " + create_jwt_token(user)},
    # )
    # assert response.status_code == 200
    # assert response.json()["status"] == "success"


@pytest.mark.django_db(transaction=True)
def test_delete_saved_search_by_user_without_access_fails():
    pass
    # user = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.STANDARD,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # user1 = User.objects.create(
    #     firstName="",
    #     lastName="",
    #     email=f"{secrets.token_hex(4)}@example.com",
    #     userType=UserType.STANDARD,
    #     createdAt=datetime.now(),
    #     updatedAt=datetime.now(),
    # )
    # search = SavedSearch.objects.create(
    #     name=f"test-{secrets.token_hex(4)}",
    #     count=3,
    #     sortDirection="",
    #     sortField="",
    #     searchTerm="",
    #     searchPath="",
    #     filters=[],
    #     createdById=user,
    # )
    # response = client.delete(
    #     f"/saved-searches/{search.id}",
    #     headers={"Authorization": "Bearer " + create_jwt_token(user1)},
    # )
    # assert response.status_code == 404


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
