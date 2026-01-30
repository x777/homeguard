"""HomeGuard Backend API."""

import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from routes.analyze import router as analyze_router  # noqa: E402

app = FastAPI(
    title="HomeGuard API",
    description="LLM proxy and CVE lookup for HomeGuard CLI",
    version="0.1.0",
)

# CORS for CLI access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(analyze_router, prefix="/api")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "llm_configured": bool(os.getenv("DEEPSEEK_API_KEY")),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
