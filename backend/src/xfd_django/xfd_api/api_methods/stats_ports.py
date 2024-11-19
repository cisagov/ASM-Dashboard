from ..auth import get_user_ports


async def get_user_ports_cache(current_user, redis_client):
    """Retrieve Stats from Elasticache."""
    try:
        # Get ports associated with the user's organizations
        user_ports = get_user_ports(current_user)

        if not user_ports:
            raise HTTPException(status_code=404, detail="No ports found for the user.")

        # Retrieve the ports stats JSON data from Redis
        ports_json = await redis_client.get("ports_stats")

        if not ports_json:
            raise HTTPException(status_code=404, detail="No ports data found in cache.")

        # Deserialize JSON data
        all_ports_data = json.loads(ports_json)

        # Filter the ports data to include only the user's ports
        ports_data = [
            port_stat for port_stat in all_ports_data if port_stat["port"] in user_ports
        ]

        if not ports_data:
            raise HTTPException(
                status_code=404, detail="No port data found for the user in cache."
            )

        return ports_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )
