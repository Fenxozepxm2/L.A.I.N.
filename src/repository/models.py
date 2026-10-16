from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# Базовый класс для моделей
class Base(DeclarativeBase):
    pass


class Host(Base):
    __tablename__ = "hosts"

    ip_address: Mapped[str] = mapped_column(String, primary_key=True)
    ip_version: Mapped[str | None] = mapped_column(String, nullable=True)
    state: Mapped[str | None] = mapped_column(String, nullable=True)
    device_name: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_os: Mapped[str | None] = mapped_column(String, nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Связь один-ко-многим: у одного хоста может быть много портов
    ports: Mapped[list["Port"]] = relationship(
        "Port", back_populates="host", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Внешний ключ, связывающий порт с хостом
    ip_address: Mapped[str] = mapped_column(
        String, ForeignKey("hosts.ip_address", ondelete="CASCADE"), nullable=False
    )

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    service_name: Mapped[str | None] = mapped_column(String, nullable=True)
    product: Mapped[str | None] = mapped_column(String, nullable=True)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    cpe: Mapped[str | None] = mapped_column(String, nullable=True)
    extra_info: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    host: Mapped["Host"] = relationship("Host", back_populates="ports")
