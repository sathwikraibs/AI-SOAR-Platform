from sqlalchemy import Column, Integer, String, DateTime
from database.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="Open")
    ip = Column(String, nullable=True)
    hash = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False)