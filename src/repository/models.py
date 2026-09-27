import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    String,
    UniqueConstraint,
)


from datetime import datetime
from typing import List, Optional
from sqlalchemy import ForeignKey, String, Integer, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Базовый класс для моделей
class Base(DeclarativeBase):
    pass


class Host(Base):
    __tablename__ = "hosts"

    ip_address: Mapped[str] = mapped_column(String, primary_key=True)
    ip_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    device_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    detected_os: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Связь один-ко-многим: у одного хоста может быть много портов
    ports: Mapped[List["Port"]] = relationship(
        "Port", 
        back_populates="host", 
        cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Внешний ключ, связывающий порт с хостом
    ip_address: Mapped[str] = mapped_column(
        String, 
        ForeignKey("hosts.ip_address", ondelete="CASCADE"), 
        nullable=False
    )
    
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    service_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    extra_info: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


    host: Mapped["Host"] = relationship("Host", back_populates="ports")
