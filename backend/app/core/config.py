from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "CloudGuard"
    api_prefix: str = "/api/v1"
    allowed_origins: list[str] = ["http://localhost:5173"]


settings = Settings()
