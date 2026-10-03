from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.firewall.hybrid_detector import hybrid_detect
from app.database.logger import log_security_event


app = FastAPI(title="AI Prompt Injection Firewall")


# Allow the frontend website to communicate with the FastAPI backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PromptRequest(BaseModel):
    prompt: str


@app.get("/")
def home():
    return {
        "project": "AI Prompt Injection Firewall",
        "status": "running"
    }


@app.post("/analyze")
def analyze_prompt(request: PromptRequest):

    # Analyze the prompt using the hybrid firewall
    result = hybrid_detect(request.prompt)

    # Save the security event in PostgreSQL
    log_security_event(request.prompt, result)

    # Return the firewall result
    return result