from fastapi import Request, HTTPException, status
from dotenv import load_dotenv
import os

load_dotenv()

"""
Fixed Window Counter 

- Unique key in Redis is generated
- Value of the key is incremented during a set time period window (ex. 60 seconds)
- If the value exceeds the limit, error is returned 
- A new window automatically resets the count 
"""

# Establish a redis connection
if os.getenv("UPSTASH_REDIS_REST_URL"):
    # For production, use Upstash Redis REST
    from upstash_redis.asyncio import Redis

    r = Redis.from_env()
    is_rest = True
else:
    # For development use standard redis TCP
    import redis.asyncio as redis

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    r = redis.from_url(
        redis_url, decode_responses=True
    )  # decode-responses returns a string instead of a byte, making it easier to work with

    is_rest = False


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds

    async def __call__(self, request: Request):
        # Disable rate limiting if env variable is set
        if os.getenv("DISABLE_RATE_LIMITING") == "1":
            return

        # Get client IP address and generate user-unique key
        forwarded = request.headers.get("X-Forwarded-For")
        client_ip = (
            forwarded.split(",")[0]
            if forwarded
            else (request.client.host or "unknown")  # type:ignore
        )
        window_key = f"rate_limit:{request.url.path}:{client_ip}"

        current_count = await r.incr(window_key)  # type: ignore
        if current_count == 1:
            await r.expire(window_key, self.window_seconds)  # type: ignore

        # Exception: Raises an error if the visit count by the IP extends the limit
        if int(current_count) > self.limit:  # type: ignore
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many attempts. Try again in a minute",
            )
