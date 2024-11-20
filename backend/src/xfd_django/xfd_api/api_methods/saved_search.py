"""Saved Search API"""


# Standard Python Libraries
from datetime import datetime, timezone
import json
import uuid

# Third-Party Libraries
from django.http import JsonResponse
from fastapi import HTTPException

from ..models import SavedSearch, User
from ..schema_models.saved_search import SavedSearchFilters


def validate_name(value: str):
    name = value.strip()
    if name == "":
        raise HTTPException(status_code=400, detail="Name cannot be empty")

    all_saved_searches = SavedSearch.objects.all()
    for search in all_saved_searches:
        if search.name.strip() == name:
            raise HTTPException(status_code=400, detail="Name already exists")


def create_saved_search(request):
    try:
        validate_name(request.get("name"))

        search = SavedSearch.objects.create(
            name=request.get("name"),
            count=request.get("count", 0),  # Default to 0 if count does not exist
            sortDirection=request.get("sortDirection", ""),
            sortField=request.get("sortField", ""),
            searchTerm=request.get("searchTerm", ""),
            searchPath=request.get("searchPath", ""),
            filters=[
                {
                    "type": "any",
                    "field": request.get("field", ""),
                    "values": [request.get("values", "")],
                }
            ],
            createdById=request.get("createdById"),
        )

        response = {
            "id": str(search.id),
            "createdAt": search.createdAt,
            "updatedAt": search.updatedAt,
            "name": search.name,
            "searchTerm": search.searchTerm,
            "sortDirection": search.sortDirection,
            "sortField": search.sortField,
            "count": search.count,
            "filters": search.filters,
            "searchPath": search.searchPath,
            "createdById": search.createdById.id,
        }

        search.save()
        return response

    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


def list_saved_searches(user):
    """List all saved searches."""
    try:
        all_saved_searches = SavedSearch.objects.all()
        saved_search_list = []
        for search in all_saved_searches:
            if search.createdById != user:
                continue
            response = {
                "id": str(search.id),
                "createdAt": search.createdAt,
                "updatedAt": search.updatedAt,
                "name": search.name,
                "searchTerm": search.searchTerm,
                "sortDirection": search.sortDirection,
                "sortField": search.sortField,
                "count": search.count,
                "filters": search.filters,
                "searchPath": search.searchPath,
                "createdById": search.createdById.id,
            }
            saved_search_list.append(response)
        return list(saved_search_list)
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


def get_saved_search(saved_search_id, user):
    if user.userType == "globalView":
        raise HTTPException(
            status_code=404, detail="Global View users cannot retrieve saved searches."
        )

    try:
        if not uuid.UUID(saved_search_id):
            raise HTTPException({"error": "Invalid UUID"}, status=404)

        saved_search = SavedSearch.objects.get(id=saved_search_id)

        if saved_search.createdById.id != user.id:
            raise HTTPException(status_code=404, detail="Saved search not found")

        response = {
            "id": str(saved_search.id),
            "createdAt": saved_search.createdAt,
            "updatedAt": saved_search.updatedAt,
            "name": saved_search.name,
            "searchTerm": saved_search.searchTerm,
            "sortDirection": saved_search.sortDirection,
            "sortField": saved_search.sortField,
            "count": saved_search.count,
            "filters": saved_search.filters,
            "searchPath": saved_search.searchPath,
            "createdById": saved_search.createdById.id,
        }
        return response
    except SavedSearch.DoesNotExist as dne:
        raise HTTPException(status_code=404, detail=str(dne))
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


def update_saved_search(request, user):
    try:
        if not uuid.UUID(request["saved_search_id"]):
            raise HTTPException(status_code=404, detail={"error": "Invalid UUID"})

        saved_search = SavedSearch.objects.get(id=request["saved_search_id"])
        if saved_search.createdById.id != user.id:
            raise HTTPException(status_code=404, detail="Saved search not found")

        saved_search.name = request["name"]
        saved_search.updatedAt = datetime.now(timezone.utc)
        saved_search.searchTerm = request["searchTerm"]
        validate_name(request.get("name"))

        saved_search.save()
        response = {
            "name": saved_search.name,
            "updatedAt": saved_search.updatedAt,
            "searchTerm": saved_search.searchTerm,
            "sortDirection": saved_search.sortDirection,
            "sortField": saved_search.sortField,
            "count": saved_search.count,
            "filters": saved_search.filters,
            "searchPath": saved_search.searchPath,
        }
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")
    except SavedSearch.DoesNotExist as dne:
        raise HTTPException(status_code=404, detail=str(dne))
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

    return response


def delete_saved_search(saved_search_id, user):
    """Delete saved search by id."""

    try:
        if not uuid.UUID(saved_search_id):
            raise HTTPException(status_code=404, detail={"error": "Invalid UUID"})
        search = SavedSearch.objects.get(id=saved_search_id)
        if search.createdById.id != user.id:
            raise HTTPException(status_code=404, detail="Saved search not found")
        search.delete()
        return JsonResponse(
            {
                "status": "success",
                "message": f"Saved search id:{saved_search_id} deleted.",
            }
        )
    except User.DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")
    except SavedSearch.DoesNotExist as dne:
        raise HTTPException(status_code=404, detail=str(dne))
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
