import json
from typing import List
from datetime import datetime
from sqlalchemy import Column, Integer, String, Date, Float
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqalchemy.orm import declarative_base, sessionmaker


class Adventure(Base):

    __tablename__ = 'adventures'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(Text)
    country = Column(String)
    date = Column(Date)
    duration= Column(Integer)
    difficulty = Column(String)
    price = Column(Float)
    available_slots = Column(Integer)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

    def to_dict(self):

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'country': self.country,
            'date': self.date,
            'duration': self.duration,
            'difficulty': self.difficulty,
            'price': self.price,
            'available_slots': self.available_slots,
            'created_at': self.created_at if self.created_at else None,
            'updated_at': self.updated_at if self.updated_at else None
        }