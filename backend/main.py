"""IntentOS backend wrapper (scaffold).

Minimal FastAPI service that can later delegate
to the main 'root' engine at:

    C:\Users\Albert Morin\Documents\Intentos\root
"""
from fastapi import FastAPI
import uvicorn
import os
from admin_routes_training import router as training_router

app = FastAPI(title="IntentOS Backend (scaffold)")

app.include_router(training_router)

ROOT_ENGINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "root"))

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "backend",
        "root_exists": os.path.exists(ROOT_ENGINE),
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
