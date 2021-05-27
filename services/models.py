import enum

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    UniqueConstraint,
    ForeignKey,
)
from sqlalchemy.types import Enum
from sqlalchemy.orm import relationship


class IPAccessEnum(enum.Enum):
    deny = 'deny'
    allow = 'allow'


Base = declarative_base()


class Route(Base):
    __tablename__ = 'routes'

    id = Column(
        Integer,
        primary_key=True,
    )
    label = Column(
        String(200),
        nullable=False,
    )
    block_by_default = Column(Boolean, default=True)
    countries = relationship(
        'Country',
        backref='routes',
        cascade='delete',
    )

    __table_args__ = (
        UniqueConstraint('label'),
    )


class Country(Base):
    __tablename__ = 'countries'

    id = Column(
        Integer,
        primary_key=True,
    )
    code = Column(
        String(100),
        nullable=False,
    )
    is_blocked = Column(
        Boolean,
        nullable=False,
    )
    route_id = Column(
        Integer,
        ForeignKey('routes.id'),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            'route_id',
            'code',
            name='_country_route_uc',
        ),
    )


class IPAccessControlList(Base):
    __tablename__ = 'ip_access_control_list'

    id = Column(Integer, primary_key=True)
    access = Column(
        Enum(IPAccessEnum, native_enum=False),
        default=IPAccessEnum.allow,
    )
    address = Column(String(100), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            'access',
            'address',
            name='_ipc_access_address_uc',
        ),
    )


class ISOCountryCodes(Base):
    __tablename__ = 'iso_country_codes'

    id = Column(
        Integer,
        primary_key=True,
    )
    name = Column(
        String(255),
        nullable=False,
    )
    code = Column(
        String(10),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            'code',
        ),
    )
