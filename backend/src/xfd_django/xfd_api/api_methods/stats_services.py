# Third-Party Libraries
from xfd_api.auth import (
    get_current_active_user,
    get_tag_organization_ids,
    get_user_domains,
    get_user_organization_ids,
    get_user_ports,
    get_user_service_ids,
    is_global_view_admin,
)


async def get_user_services_count(current_user, redis_client):
    """Retrieve services from Elasticache filtered by user."""
    try:
        # Get service IDs associated with the user's organizations
        user_service_ids = get_user_service_ids(current_user)

        if not user_service_ids:
            raise HTTPException(
                status_code=404, detail="No services found for the user."
            )

        services_data = []

        # Fetch data from Redis for each service ID
        for service_id in user_service_ids:
            service_data = await redis_client.get(service_id)
            if service_data:
                try:
                    # Attempt to parse the service_data as JSON
                    parsed_data = json.loads(service_data)
                    services_data.append({"id": service_id, "value": parsed_data})
                except json.JSONDecodeError:
                    # If not JSON, assume it's an integer-like string and convert
                    services_data.append({"id": service_id, "value": int(service_data)})

        if not services_data:
            raise HTTPException(
                status_code=404, detail="No service data found in cache."
            )

        return services_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )
