from abc import ABC, abstractmethod

from sqlalchemy.exc import IntegrityError

from .models import (
    Route,
    Country,
    IPAccessControlList,
    ISOCountryCodes,
)


class IBlockService(ABC):

    @abstractmethod
    def create_route(self, label: str, block_by_default: bool):
        """"""

    @abstractmethod
    def create_routes_country(self, label: str,
                              code: str, is_blocked: bool):
        """"""

    @abstractmethod
    def get_all_routes(self):
        """"""

    @abstractmethod
    def get_route_by_label(self, label: str):
        """"""

    @abstractmethod
    def get_route_by_id(self, pk: int):
        """"""

    @abstractmethod
    def get_routes_country_by_label(self, label: str, code: str):
        """"""

    @abstractmethod
    def get_country_by_code(self, code: str):
        """"""

    @abstractmethod
    def get_country_by_id(self, pk: int):
        """"""

    @abstractmethod
    def drop_route_country(self, label: str, code: str):
        """"""

    @abstractmethod
    def drop_route(self, label: str):
        """"""

    @abstractmethod
    def drop_routes(self):
        """"""

    @abstractmethod
    def get_all_countries(self):
        """"""

    @abstractmethod
    def drop_route_countries(self, label: str):
        """"""

    @abstractmethod
    def set_route_block_by_default(self, label: str,
                                   block_by_default: bool):
        """"""

    @abstractmethod
    def get_ip_access_controls(self):
        """"""

    @abstractmethod
    def create_ip_access_control(self, access: str, address: str):
        """"""

    @abstractmethod
    def get_ip_access_control_by_id(self, pk: int):
        """"""

    @abstractmethod
    def drop_ip_access_control(self, pk):
        """"""

    @abstractmethod
    def drop_all_access_control(self):
        """"""

    @abstractmethod
    def change_access_control_address(self, pk: int, address: str):
        """"""

    @abstractmethod
    def change_access_control_access(self, pk: int, access: str):
        """"""

    @abstractmethod
    def drop_all(self):
        """"""


class SqliteBlockService(IBlockService):
    def __init__(self, session):
        self.session = session

    def create_route(self, label, block_by_default=True):
        try:
            route = Route(label=label,
                          block_by_default=block_by_default)
            self.session.add(route)
            self.session.flush()

            return route

        except IntegrityError:
            raise ServiceIntegrityError(
                'route already exists'
            )

    def get_all_routes(self):
        return self.session.query(Route).all()

    def get_route_by_label(self, label):
        return self.session.query(Route).filter_by(
            label=label,
        ).one_or_none()

    def get_route_by_id(self, pk):
        return self.session.query(Route).filter_by(
            id=pk,
        ).one_or_none()

    def get_country_by_code(self, code):
        return self.session.query(Country).filter_by(
            code=code,
        ).one_or_none()

    def get_country_by_id(self, pk):
        return self.session.query(Country).filter_by(
            id=pk,
        ).one_or_none()

    def get_routes_country_by_label(self, label, code):
        return self.session.query(Country).filter_by(
            code=code,
        ).join(Route).filter_by(
            label=label,
        ).one_or_none()

    def drop_route_country(self, label, code):
        countries = self.session.query(Country).filter_by(
            code=code,
        ).join(Route).filter_by(
            label=label,
        )
        if countries.count() == 0:
            raise ServiceNotFoundError('country or route not found')

        for country in countries:
            self.session.delete(country)

        self.session.flush()

    def drop_route_countries(self, label):
        route = self.session.query(Route).filter_by(
            label=label,
        ).one_or_none()

        if not route:
            raise ServiceNotFoundError('route not found')

        for country in route.countries:
            self.session.delete(country)

        self.session.flush()

    def drop_route(self, label):
        country = self.session.query(Route).filter_by(
            label=label,
        ).one_or_none()

        if not country:
            raise ServiceNotFoundError(
                'route not found'
            )

        self.session.delete(country)
        self.session.flush()

    def get_all_countries(self):
        return self.session.query(Country).all()

    def set_route_block_by_default(self, label, block_by_default):
        route = self.session.query(Route).filter_by(
            label=label,
        ).one_or_none()

        if not route:
            raise ServiceNotFoundError(
                'route not found'
            )

        route.block_by_default = block_by_default
        self.session.add(route)
        self.session.flush()

    def create_routes_country(self, label, code, is_blocked):
        route = self.get_route_by_label(label)

        if not route:
            raise ServiceNotFoundError(
                'route not found'
            )
        try:
            country = Country(
                code=code,
                is_blocked=is_blocked,
                route_id=route.id,
            )

            self.session.add(country)
            self.session.flush()

            return route

        except IntegrityError:
            raise ServiceIntegrityError(
                'record already exists'
            )

    def iso_country_code_add_row(self, name, code):
        try:
            row = ISOCountryCodes(name=name, code=code)
            self.session.add(row)
            self.session.flush()

            return row
        except IntegrityError:
            raise ServiceIntegrityError(
                'row already exists:\nname - {}\ncode - {}\n'.format(
                    name,
                    code,
                )
            )

    def iso_country_codes_all(self):
        return self.session.query(ISOCountryCodes).all()

    def iso_country_codes_drop_all(self):
        self.session.query(ISOCountryCodes).delete()
        self.session.flush()

    def get_ip_access_controls(self):
        return self.session.query(IPAccessControlList).order_by(
            IPAccessControlList.id,
        ).all()

    def get_ip_access_control_by_id(self, pk):
        return self.session.query(IPAccessControlList).get(pk)

    def create_ip_access_control(self, access: str, address: str):
        try:
            ip_access_control = IPAccessControlList(
                access=access,
                address=address,
            )
            self.session.add(ip_access_control)
            self.session.flush()

            return ip_access_control

        except IntegrityError:
            raise ServiceIntegrityError(
                'ip access control already exists'
            )

    def drop_ip_access_control(self, pk):
        ip_access_control = self.session.query(
            IPAccessControlList,
        ).get(pk)
        if not ip_access_control:
            raise ServiceNotFoundError('ip access control not found')

        self.session.delete(ip_access_control)
        self.session.flush()

    def drop_all_access_control(self):
        self.session.query(IPAccessControlList).delete()
        self.session.flush()

    def change_access_control_address(self, pk, address):
        ipacl = self.session.query(IPAccessControlList).get(pk)
        if not ipacl:
            raise ServiceNotFoundError('ip access control not found')

        ipacl.address = address
        try:
            self.session.add(ipacl)
            self.session.flush()
        except IntegrityError:
            raise ServiceIntegrityError('record already exists')

    def change_access_control_access(self, pk, access):
        ipacl = self.session.query(IPAccessControlList).get(pk)
        if not ipacl:
            raise ServiceNotFoundError('ip access control not found')
        ipacl.access = access
        try:
            self.session.add(ipacl)
            self.session.flush()
        except IntegrityError:
            raise ServiceIntegrityError('wrong access directive|record already exists')

    def drop_all(self):
        self.session.query(Route).delete()
        self.session.query(Country).delete()
        self.session.query(ISOCountryCodes).delete()
        self.session.query(IPAccessControlList).delete()

        self.session.flush()

    def drop_routes(self):
        self.session.query(Route).delete()


class BlockServiceError(Exception):
    pass


class ServiceIntegrityError(BlockServiceError):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class ServiceNotFoundError(BlockServiceError):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message
