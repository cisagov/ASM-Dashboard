# Standard Python Libraries
from collections import defaultdict
import json

# Third-Party Libraries
from fastapi import HTTPException, Request
from redis import asyncio as aioredis
from xfd_api.auth import get_stats_org_ids
from xfd_api.helpers.stats_helpers import get_stats_count_from_cache, get_total_count, safe_redis_mget


# GET: /stats
async def get_stats(filter_data, current_user, redis_client, request: Request):
    """Compile all stats."""

    async def safe_fetch(fetch_fn, *args, **kwargs):
        """Safely fetch stats, returning an empty list on failure."""
        try:
            return await fetch_fn(*args, **kwargs)
        except Exception as e:
            print(f"Error fetching stats with {fetch_fn.__name__}: {e}")
            return []

    filtered_org_ids = get_stats_org_ids(current_user, filter_data)

    # Ensure organization_ids is not empty
    if not filtered_org_ids:
        raise HTTPException(
            status_code=404,
            detail="No organizations found for the user with the specified filters.",
        )

    # Fetch
    try:
        return {
            "result": {
                "domains": {
                    "services": await safe_fetch(
                        get_user_services_count,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "ports": await safe_fetch(
                        get_user_ports_count,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "numVulnerabilities": await safe_fetch(
                        get_num_vulns,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "total": await safe_fetch(get_total_count, filtered_org_ids),
                },
                "vulnerabilities": {
                    "severity": await safe_fetch(
                        get_severity_stats,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "latestVulnerabilities": await safe_fetch(
                        stats_latest_vulns,
                        filter_data,
                        current_user,
                        redis_client,
                        request,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "mostCommonVulnerabilities": await safe_fetch(
                        stats_most_common_vulns,
                        filter_data,
                        current_user,
                        redis_client,
                        request,
                        filtered_org_ids=filtered_org_ids,
                    ),
                    "byOrg": await safe_fetch(
                        get_by_org_stats,
                        filter_data,
                        current_user,
                        redis_client,
                        filtered_org_ids=filtered_org_ids,
                    ),
                },
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


async def get_user_services_count(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Retrieve services from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        services_data = await get_stats_count_from_cache(
            redis_client, "services_stats", filtered_org_ids
        )

        if not services_data:
            raise HTTPException(
                status_code=404,
                detail="No service data found for the user's organizations in cache.",
            )

        return services_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


async def get_user_ports_count(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Retrieve ports from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        ports_data = await get_stats_count_from_cache(
            redis_client, "ports_stats", filtered_org_ids
        )

        if not ports_data:
            raise HTTPException(
                status_code=404,
                detail="No port data found for the user's organizations in cache.",
            )

        return ports_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


async def get_num_vulns(filter_data, current_user, redis_client, filtered_org_ids=None):
    """Retrieve ports from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        num_vulns_data = await get_stats_count_from_cache(
            redis_client, "vulnerabilities_stats", filtered_org_ids
        )

        if not num_vulns_data:
            raise HTTPException(
                status_code=404,
                detail="No port data found for the user's organizations in cache.",
            )

        return num_vulns_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


async def get_severity_stats(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """Retrieve ports from Elasticache filtered by user."""
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        severity_data = await get_stats_count_from_cache(
            redis_client, "severity_stats", filtered_org_ids
        )

        if not severity_data:
            raise HTTPException(
                status_code=404,
                detail="No severity data found for the user's organizations in cache.",
            )

        return severity_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {e}"
        )


async def stats_latest_vulns(
    filter_data, current_user, redis_client, request: Request, max_results=50, filtered_org_ids=None
):
    """
    Retrieve the latest vulnerabilities from Elasticache filtered by user.
    """
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        # Generate all Redis keys at once
        redis_keys = [f"latest_vulnerabilities:{org_id}" for org_id in filtered_org_ids]

        # Use MGET to fetch all keys in a single operation
        results = await safe_redis_mget(redis_client, redis_keys, request.app.state.redis_semaphore)

        vulnerabilities = []

        # Process the results, skip None values
        for data in results:
            if data:
                vulnerabilities.extend(json.loads(data))

        # Limit the results to the maximum specified
        vulnerabilities = sorted(vulnerabilities, key=lambda x: x["createdAt"])[
            :max_results
        ]

        if not vulnerabilities:
            raise HTTPException(
                status_code=404,
                detail="No vulnerabilities found for the user's organizations in cache.",
            )

        return vulnerabilities

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {e}",
        )


async def stats_most_common_vulns(
    filter_data, current_user, redis_client, request: Request, max_results=10, filtered_org_ids=None
):
    """
    Retrieve the most common vulnerabilities from Elasticache filtered by user.
    """
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        # Generate all Redis keys at once
        redis_keys = [
            f"most_common_vulnerabilities:{org_id}" for org_id in filtered_org_ids
        ]

        # Use MGET to fetch all keys in a single operation
        results = await safe_redis_mget(redis_client, redis_keys, request.app.state.redis_semaphore)

        vulnerabilities = []

        # Process the results, skip None values
        for data in results:
            if data:
                vulnerabilities.extend(json.loads(data))

        # Limit the results to the maximum specified
        vulnerabilities = sorted(vulnerabilities, key=lambda x: x["count"])[
            :max_results
        ]

        return vulnerabilities

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {e}",
        )


async def get_by_org_stats(
    filter_data, current_user, redis_client, filtered_org_ids=None
):
    """
    Fetch the count of open vulnerabilities grouped by organization from Redis.
    """
    try:
        if not filtered_org_ids:
            filtered_org_ids = get_stats_org_ids(current_user, filter_data)

            # Ensure organization_ids is not empty
            if not filtered_org_ids:
                raise HTTPException(
                    status_code=404,
                    detail="No organizations found for the user with the specified filters.",
                )

        # Initialize the results list
        by_org_data = []

        # Fetch data from Redis for each organization ID
        for org_id in filtered_org_ids:
            redis_key = f"by_org_stats:{org_id}"
            org_stats = await redis_client.get(redis_key)
            if org_stats:
                by_org_data.append(
                    json.loads(org_stats)
                )  # Directly append the Redis data

        if not by_org_data:
            raise HTTPException(
                status_code=404,
                detail="No organization data found in cache.",
            )

        return by_org_data

    except aioredis.RedisError as redis_error:
        raise HTTPException(status_code=500, detail=f"Redis error: {redis_error}")

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {e}",
        )
