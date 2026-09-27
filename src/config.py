import tomllib
from dataclasses import dataclass


@dataclass
class Database:
    url: str


@dataclass
class Config:
    database_url: Database


def load_config() -> Config:
    with open("settings.toml", "rb") as file:
        data = tomllib.load(file)
    return Config(
        database_url=Database(url=data["database_url"]["url"])
    )

