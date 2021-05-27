import sys
import os

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, base_dir)

import csv
import pytest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


from tabulate import tabulate

from click.testing import CliRunner
from block import (
    cli,
    render
)
from services.models import (
    Base,
    Route,
    Country,
    ISOCountryCodes,
    IPAccessControlList,
    IPAccessEnum,
)
from services.geo_block import (
    SqliteBlockService,
    ServiceIntegrityError,
    ServiceNotFoundError,
)
from validators import (
    validate_ip,
    validate_subnet,
    validate_nginx_phrase,
    validate_address,
    ValidationError,
)


@pytest.fixture
def session():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)

    session = sessionmaker(
        bind=engine,
        autoflush=True,
        autocommit=True,

    )()

    yield session

    session.query(Route).delete()
    session.query(Country).delete()
    session.query(ISOCountryCodes).delete()
    session.query(IPAccessControlList).delete()

    session.flush()
    session.close()


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def route(session):
    route = Route(
        label='test',
        block_by_default=True,
    )
    session.add(route)
    session.flush()

    return route


@pytest.fixture
def country(session, route):
    country = Country(
        code='UA',
        is_blocked=False,
        route_id=route.id,
    )
    session.add(country)
    session.flush()

    return country


@pytest.fixture
def countries(session, route):
    country_ua = Country(
        code='UA',
        is_blocked=False,
        route_id=route.id,
    )
    country_br = Country(
        code='BR',
        is_blocked=False,
        route_id=route.id,
    )
    session.add(country_ua)
    session.add(country_br)
    session.flush()

    return [
        country_ua,
        country_br
    ]


@pytest.fixture
def routes(session):
    routes = [
        Route(
            label='test_{}'.format(1),
            block_by_default=True,
        ),
        Route(
            label='test_{}'.format(2),
            block_by_default=False,
        ),
        Route(
            label='test_{}'.format(3),
            block_by_default=False,
        )
    ]
    session.add_all(routes)
    session.flush()

    return routes


@pytest.fixture
def code(session):
    co = ISOCountryCodes(name='Ukraine', code='UA')
    session.add(co)
    session.flush()

    return co


@pytest.fixture
def ip_acl(session):
    ip_acl = IPAccessControlList(access='allow', address='all')
    session.add(ip_acl)
    session.flush()

    return ip_acl


@pytest.fixture
def ip_acl_many(session):
    ip_acl_all = IPAccessControlList(access='allow', address='all')
    ip_acl_ip = IPAccessControlList(access='deny', address='195.31.25.44')
    ip_acl_subnet = IPAccessControlList(access='deny', address='195.31.25.0/24')

    session.add(ip_acl_all)
    session.add(ip_acl_ip)
    session.add(ip_acl_subnet)
    session.flush()

    return [
        ip_acl_all,
        ip_acl_ip,
        ip_acl_subnet,
    ]


@pytest.fixture
def sqlite_block_service(session):
    return SqliteBlockService(session)


class TestSqliteBlockService:

    def test_create_route(self, sqlite_block_service):
        route = sqlite_block_service.create_route(
            label='test',
            block_by_default=True,
        )

        assert route.label == 'test'
        assert route.block_by_default

    def test_create_route_exists(self, route, sqlite_block_service):
        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.create_route(
                label='test',
                block_by_default=True,
            )

    def test_get_all_routes(self, routes, sqlite_block_service):
        obj_id = 0
        assert sorted(
            [
                (route.id, route.label, route.block_by_default)
                for route in routes
            ],
            key=lambda x: obj_id,
        ) == sorted(
            [
                (route.id, route.label, route.block_by_default)
                for route in sqlite_block_service.get_all_routes()
            ],
            key=lambda x: obj_id,
        )

    def test_get_route_by_label(self, route, sqlite_block_service):
        assert route.id == sqlite_block_service.get_route_by_label('test').id

    def test_get_route_by_label_not_found(self, sqlite_block_service):
        assert sqlite_block_service.get_route_by_label('test') is None

    def test_get_route_by_id(self, route, sqlite_block_service):
        assert route.id == sqlite_block_service.get_route_by_id(1).id

    def test_get_route_by_id_not_found(self, sqlite_block_service):
        assert sqlite_block_service.get_route_by_id(1) is None

    def test_get_country_by_code(self, country, sqlite_block_service):
        assert country.id == sqlite_block_service.get_country_by_code('UA').id

    def test_get_country_by_code_not_found(self, sqlite_block_service):
        assert sqlite_block_service.get_country_by_code('UA') is None

    def test_get_country_by_id(self, country, sqlite_block_service):
        assert country.id == sqlite_block_service.get_country_by_id(1).id

    def test_get_country_by_id_not_found(self, sqlite_block_service):
        assert sqlite_block_service.get_country_by_id(1) is None

    def test_get_routes_country_by_label(self, country, sqlite_block_service):
        assert (
                country.id ==
                sqlite_block_service.get_routes_country_by_label('test', 'UA').id
        )

    def test_get_routes_country_by_label_not_found_route(self, country, sqlite_block_service):
        assert sqlite_block_service.get_routes_country_by_label('test1', 'UA') is None

    def test_get_routes_country_by_label_not_found_country(self, country, sqlite_block_service):
        assert sqlite_block_service.get_routes_country_by_label('test', 'BR') is None

    def test_drop_route_country(self, countries, sqlite_block_service):
        sqlite_block_service.drop_route_country('test', 'UA')

        assert sqlite_block_service.get_routes_country_by_label('test', 'UA') is None

    def test_drop_all(self, route, code, country, sqlite_block_service):
        sqlite_block_service.drop_all()

        assert sqlite_block_service.get_all_routes() == []
        assert sqlite_block_service.iso_country_codes_all() == []
        assert sqlite_block_service.get_all_countries() == []

    def test_drop_routes(self, route, sqlite_block_service):
        sqlite_block_service.drop_routes()

        assert sqlite_block_service.get_all_routes() == []

    def test_drop_route_country_not_found_route(self, countries, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.drop_route_country('NotExists', 'UA')

    def test_drop_route_country_not_found_country(self, countries, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.drop_route_country('test', 'NotExists')

    def test_drop_route_countries(self, countries, sqlite_block_service):
        sqlite_block_service.drop_route_countries('test')

        assert sqlite_block_service.get_routes_country_by_label('test', 'UA') is None
        assert sqlite_block_service.get_routes_country_by_label('test', 'BR') is None

    def test_drop_route_countries_not_found_route(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.drop_route_countries('test')

    def test_drop_route(self, route, sqlite_block_service):
        sqlite_block_service.drop_route('test')

        assert sqlite_block_service.get_route_by_id('test') is None

    def test_drop_route_not_found(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.drop_route('test')

    def test_set_route_block_by_default(self, route, sqlite_block_service):
        sqlite_block_service.set_route_block_by_default('test', False)

        assert sqlite_block_service.get_route_by_label('test').block_by_default == False

    def test_set_route_block_by_default_not_found(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.set_route_block_by_default('test', False)

    def test_get_all_countries(self, countries, sqlite_block_service):
        assert sorted([
                   country.id
                   for country in countries
               ]) == \
               sorted([
                   country.id
                   for country in sqlite_block_service.get_all_countries()
               ])

    def test_create_routes_country(self, route, sqlite_block_service):
        sqlite_block_service.create_routes_country('test', 'UA', True)

        assert sqlite_block_service.get_routes_country_by_label('test', 'UA')

    def test_create_routes_country_not_found(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.create_routes_country('test', 'UA', True)

    def test_create_routes_country_already_exists(self, countries, sqlite_block_service):
        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.create_routes_country('test', 'UA', True)

    def test_iso_country_code_add_row(self, sqlite_block_service):
        code = sqlite_block_service.iso_country_code_add_row('Ukraine', 'UA')
        assert [
            code.id,
        ] == [
            code.id
            for code in sqlite_block_service.iso_country_codes_all()
        ]

    def test_iso_country_code_add_row_already_exists(self, code,  sqlite_block_service):
        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.iso_country_code_add_row('Ukraine', 'UA')

    def test_iso_country_codes_drop_all(self, code, sqlite_block_service):
        sqlite_block_service.iso_country_codes_drop_all()
        assert sqlite_block_service.iso_country_codes_all() == []

    def test_get_ip_access_controls(self, ip_acl, sqlite_block_service):
        assert [
                   ip_acl.id,
               ] == \
               [
                   obj.id
                   for obj in sqlite_block_service.get_ip_access_controls()
               ]

    def test_get_ip_access_control_by_id(self, ip_acl, sqlite_block_service):
        assert ip_acl.id == sqlite_block_service.get_ip_access_control_by_id(1).id

    def test_get_ip_access_control_by_id_already_exists(self, ip_acl, sqlite_block_service):
        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.create_ip_access_control(access='allow', address='all')

    def test_create_ip_access_control(self, sqlite_block_service):
        obj = sqlite_block_service.create_ip_access_control(access='allow', address='all')

        assert obj.id == sqlite_block_service.get_ip_access_control_by_id(1).id

    def test_drop_ip_access_control(self, ip_acl, sqlite_block_service):
        sqlite_block_service.drop_ip_access_control(1)

        assert sqlite_block_service.get_ip_access_control_by_id(1) is None

    def test_drop_ip_access_control_not_found(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.drop_ip_access_control(1)

    def test_drop_all_access_control(self, ip_acl, sqlite_block_service):
        sqlite_block_service.drop_all_access_control()

        assert sqlite_block_service.get_ip_access_controls() == []

    def test_change_access_control_address(self, ip_acl, sqlite_block_service):
        sqlite_block_service.change_access_control_address(1, '127.0.0.1')
        assert sqlite_block_service.get_ip_access_control_by_id(1).address == '127.0.0.1'

    def test_change_access_control_address_not_found(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.change_access_control_address(1, '127.0.0.1')

    def test_change_access_control_address_already_exists(self, ip_acl, sqlite_block_service):
        sqlite_block_service.create_ip_access_control(access='allow', address='127.0.0.1')

        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.change_access_control_address(1, '127.0.0.1')

    def test_change_access_control_access(self, ip_acl, sqlite_block_service):
        sqlite_block_service.change_access_control_access(1, 'deny')
        assert sqlite_block_service.get_ip_access_control_by_id(1).access.value == 'deny'

    def test_change_access_control_access_not_found(self, sqlite_block_service):
        with pytest.raises(ServiceNotFoundError):
            sqlite_block_service.change_access_control_access(1, 'deny')

    def test_change_access_control_access_already_exists(self, ip_acl, sqlite_block_service):
        sqlite_block_service.create_ip_access_control(access='deny', address='all')

        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.change_access_control_access(1, 'deny')

    def test_change_access_control_access_wrong_access(self, ip_acl, sqlite_block_service):
        with pytest.raises(ServiceIntegrityError):
            sqlite_block_service.change_access_control_access(1, 'NonExists')

    def test_service_not_found_error(self):
        try:
            raise ServiceNotFoundError('test')
        except ServiceNotFoundError as e:
            assert str(e) == 'test'

    def test_service_integrity_error(self):
        try:
            raise ServiceIntegrityError('test')
        except ServiceIntegrityError as e:
            assert str(e) == 'test'


class TestValidators:
    def test_validate_ip_ok(self):
        assert '127.0.0.1' == str(validate_ip('127.0.0.1'))

    def test_validate_ip_fail(self):
        with pytest.raises(ValidationError):
            validate_ip('127.0.0.b')

    def test_validate_subnet_ok(self):
        assert '127.1.1.0/24' == str(validate_subnet('127.1.1.0/24'))

    def test_validate_subnet_fail(self):
        with pytest.raises(ValidationError):
            validate_subnet('127.1.1.0/33')

    def test_validate_nginx_phrase_ok(self):
        assert 'all' == validate_nginx_phrase('all')

    def test_validate_nginx_phrase_fail(self):
        with pytest.raises(ValidationError):
            validate_nginx_phrase('all1')

    def test_validate_address_ip(self):
        assert '127.0.0.1' == validate_address(
            '127.0.0.1',
            [
                validate_ip,
                validate_subnet,
                validate_nginx_phrase
            ],
        )

    def test_validate_address_subnet(self):
        assert '127.0.0.0/24' == validate_address(
            '127.0.0.0/24',
            [
                validate_ip,
                validate_subnet,
                validate_nginx_phrase
            ],
        )

    def test_validate_address_phrase(self):
        assert 'all' == validate_address(
            'all',
            [
                validate_ip,
                validate_subnet,
                validate_nginx_phrase
            ],
        )

    def test_validate_address_fail(self):
        with pytest.raises(ValidationError):
            validate_address(
                'fail',
                [
                    validate_ip,
                    validate_subnet,
                    validate_nginx_phrase
                ],
            )

    def test_validation_error(self):
        try:
            raise ValidationError('test')
        except ValidationError as e:
            assert str(e) == 'test'


@patch('block.SqliteBlockService')
def test_add_route(mock_sqlite_block_service, cli_runner, sqlite_block_service):
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'add', 'route',
        '--label', 'test',
        '--default', 'y'
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_route_by_label('test').id == 1


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_route_already_exists(mock_datetime, mock_sqlite_block_service,
                                  cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'add', 'route',
        '--label', 'test',
        '--default', 'y'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route already exists\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_route(mock_datetime, mock_sqlite_block_service,
                    cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'drop', 'route',
        '--label', 'test'
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_route_by_label('test') is None


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_route_not_found(mock_datetime, mock_sqlite_block_service,
                              cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'drop', 'route',
        '--label', 'test'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_country(mock_datetime, mock_sqlite_block_service,
                     cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'add', 'country',
        '--label', 'test',
        '--code', 'UA',
        '--is_blocked', 'y',
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_routes_country_by_label('test', 'UA').id == 1


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_country_not_found(mock_datetime, mock_sqlite_block_service,
                               cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'add', 'country',
        '--label', 'test',
        '--code', 'UA',
        '--is_blocked', 'y',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_country_already_exists(mock_datetime, mock_sqlite_block_service,
                                    cli_runner, country, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'add', 'country',
        '--label', 'test',
        '--code', 'UA',
        '--is_blocked', 'y',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: record already exists\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_country(mock_datetime, mock_sqlite_block_service,
                      cli_runner, country, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'drop', 'country',
        '--label', 'test',
        '--code', 'UA',
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_routes_country_by_label('test', 'UA') is None


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_country_not_found_route(mock_datetime, mock_sqlite_block_service,
                                      cli_runner,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'drop', 'country',
        '--label', 'test',
        '--code', 'UA',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: country or route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_country_not_found_country(mock_datetime, mock_sqlite_block_service,
                                        cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'drop', 'country',
        '--label', 'test',
        '--code', 'UA',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: country or route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_show_routes(mock_datetime, mock_sqlite_block_service,
                     cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'show', 'routes',
    ])

    route_objs = sqlite_block_service.get_all_routes()
    pk, label, block_by_default = 'id', 'label', 'block_by_default'
    header = [pk, label, block_by_default]
    data = [
        [
            getattr(route, pk),
            getattr(route, label),
            getattr(route, block_by_default),
        ] for route in route_objs
    ]

    assert result.exit_code == 0
    assert result.output == tabulate(data, header, tablefmt='grid') + '\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_show_countries(mock_datetime, mock_sqlite_block_service,
                        cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'show', 'countries',
    ])

    country_objs = sqlite_block_service.get_all_countries()
    header = ['id', 'code', 'is_blocked',
              'route_id', 'route_label', 'routes_block_by_default']
    data = []
    for country in country_objs:
        data.append([
            country.id,
            country.code,
            country.is_blocked,
            country.route_id,
            country.routes.label,
            country.routes.block_by_default,
        ])

    assert result.exit_code == 0
    assert result.output == tabulate(data, header, tablefmt='grid') + '\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_show_route_info(mock_datetime, mock_sqlite_block_service,
                         cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(cli, [
        'show', 'route',
        '--label', 'test'
    ])

    route = sqlite_block_service.get_route_by_label('test')

    string_output = 'route info:\nid: {}\nlabel: {}\nblock by default: {}\n'.format(
            route.id,
            route.label,
            route.block_by_default,
    )

    pk, code, is_blocked = 'id', 'code', 'is_blocked'
    header = [pk, code, is_blocked]
    data = [
        [
            getattr(country, pk),
            getattr(country, code),
            getattr(country, is_blocked),
        ] for country in route.countries
    ]

    assert result.exit_code == 0
    assert result.output == string_output + tabulate(data, header, tablefmt='grid') + '\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_show_route_info_not_found(mock_datetime, mock_sqlite_block_service,
                                   cli_runner,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'show', 'route',
        '--label', 'test'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route not found\n'


def test_render(route):
    assert render(
                    'country_maps.dat',
                    nginx_country_variable='geoip2_country_code',
                    routes=[
                        route,
                    ],
                ) == "map $geoip2_country_code $test {\n%sdefault True;\n}\n" % (' ' * 4, )


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_render_geo(mock_datetime, mock_sqlite_block_service,
                    cli_runner, route,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
          cli,
          [
              'render', 'geo',
              '--output', 'geo.acl'
          ]
        )
        with open('geo.acl', 'r') as f:
            file_text = f.read()

        assert result.exit_code == 0
        assert file_text == "map $geoip2_country_code $test {\n%sdefault True;\n}\n" % (' ' * 4, )


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_render_ip(mock_datetime, mock_sqlite_block_service,
                   cli_runner, ip_acl_many,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
          cli,
          [
              'render', 'ip',
              '--output', 'ip.acl'
          ]
        )
        with open('ip.acl', 'r') as f:
            file_text = f.read()

        assert result.exit_code == 0
        assert file_text == "allow all;\ndeny 195.31.25.44;\ndeny 195.31.25.0/24;\n"


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_render_ip_wrong_path(mock_datetime, mock_sqlite_block_service,
                              cli_runner, ip_acl_many,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
          cli,
          [
              'render', 'ip',
              '--output', 'ip.acl/'
          ]
        )

        assert result.exit_code == 0
        assert result.output == '1970-01-01T00:00:00Z: Is a directory\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_render_geo_wrong_path(mock_datetime, mock_sqlite_block_service,
                               cli_runner, ip_acl_many,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
          cli,
          [
              'render', 'geo',
              '--output', 'geo.acl/'
          ]
        )

        assert result.exit_code == 0
        assert result.output == '1970-01-01T00:00:00Z: Is a directory\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_ip(mock_datetime, mock_sqlite_block_service,
                cli_runner,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'add', 'ip',
        '--access', 'allow',
        '--ip', '127.0.0.1'
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_ip_access_control_by_id(1).id == 1


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_ip_validation_error(mock_datetime, mock_sqlite_block_service,
                                 cli_runner,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'add', 'ip',
        '--access', 'allow',
        '--ip', '127.0.0.1a'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: cannot convert to ip address\n' \
                            'cannot convert to network address\n' \
                            'not an nginx phrase\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_add_ip_already_exists(mock_datetime, mock_sqlite_block_service,
                               cli_runner, ip_acl,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'add', 'ip',
        '--access', 'allow',
        '--ip', 'all'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: ip access control already exists\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_ip(mock_datetime, mock_sqlite_block_service,
                 cli_runner, ip_acl,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'drop', 'ip',
        '--pk', '1',
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_ip_access_control_by_id(1) is None


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_ip_not_found(mock_datetime, mock_sqlite_block_service,
                           cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'drop', 'ip',
        '--pk', '1',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: ip access control not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_access(mock_datetime, mock_sqlite_block_service,
                         cli_runner, ip_acl, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'ip-access',
        '--pk', '1',
        '--access', 'deny',
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_ip_access_control_by_id(1).access.value == 'deny'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_access_not_found(mock_datetime, mock_sqlite_block_service,
                                   cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'ip-access',
        '--pk', '1',
        '--access', 'deny',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: ip access control not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_access_already_exists(mock_datetime, mock_sqlite_block_service,
                                        cli_runner, ip_acl_many, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    cli_runner.invoke(cli, [
        'alter', 'ip-address',
        '--pk', '1',
        '--ip', '195.31.25.44',
    ])
    result = cli_runner.invoke(cli, [
        'alter', 'ip-access',
        '--pk', '1',
        '--access', 'deny',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: wrong access directive|record already exists\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_address(mock_datetime, mock_sqlite_block_service,
                          cli_runner, ip_acl, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'ip-address',
        '--pk', '1',
        '--ip', '127.0.0.1',
    ])

    assert result.exit_code == 0
    assert str(sqlite_block_service.get_ip_access_control_by_id(1).address) == '127.0.0.1'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_address_not_found(mock_datetime, mock_sqlite_block_service,
                                   cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'ip-address',
        '--pk', '1',
        '--ip', '127.0.0.1',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: ip access control not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_address_already_exists(mock_datetime, mock_sqlite_block_service,
                                        cli_runner, ip_acl_many, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    cli_runner.invoke(cli, [
        'alter', 'ip-access',
        '--pk', '1',
        '--access', 'deny',
    ])
    result = cli_runner.invoke(cli, [
        'alter', 'ip-address',
        '--pk', '1',
        '--ip', '195.31.25.44',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: record already exists\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_ip_address_validation_error(mock_datetime, mock_sqlite_block_service,
                                           cli_runner, ip_acl_many, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'ip-address',
        '--pk', '1',
        '--ip', '195.31.25.44b',
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: cannot convert to ip address\n' \
                            'cannot convert to network address\n' \
                            'not an nginx phrase\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_show_acl(mock_datetime, mock_sqlite_block_service,
                  cli_runner, ip_acl_many, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'show', 'acl'
    ])

    ipacls = sqlite_block_service.get_ip_access_controls()
    pk, access, address = 'id', 'access', 'address'
    header = [pk, access, address]
    data = [
        [
            getattr(acl, pk),
            getattr(acl, access).value,
            getattr(acl, address),
        ] for acl in ipacls
    ]

    assert result.exit_code == 0
    assert result.output == tabulate(data, header, tablefmt='grid') + '\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_acl(mock_datetime, mock_sqlite_block_service,
                  cli_runner, ip_acl_many, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'drop', 'acl'
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_ip_access_controls() == []


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_route_countries(mock_datetime, mock_sqlite_block_service,
                              cli_runner, countries, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'drop', 'route-countries',
        '--label', 'test'
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_all_countries() == []


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_route_countries_not_found(mock_datetime, mock_sqlite_block_service,
                                        cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'drop', 'route-countries',
        '--label', 'test'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_route_countries_not_found(mock_datetime, mock_sqlite_block_service,
                                        cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'drop', 'route-countries',
        '--label', 'test'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_route_default(mock_datetime, mock_sqlite_block_service,
                             cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'route-default',
        '--label', 'test',
        '--default', 'n'
    ])

    assert result.exit_code == 0
    assert sqlite_block_service.get_route_by_label('test').block_by_default is False


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_alter_route_not_found(mock_datetime, mock_sqlite_block_service,
                             cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'alter', 'route-default',
        '--label', 'test',
        '--default', 'n'
    ])

    assert result.exit_code == 0
    assert result.output == '1970-01-01T00:00:00Z: route not found\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_show_codes(mock_datetime, mock_sqlite_block_service,
                    cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service
    result = cli_runner.invoke(cli, [
        'show', 'codes'
    ])

    country_codes = sqlite_block_service.iso_country_codes_all()
    pk, name, code = 'id', 'name', 'code'
    header = [pk, name, code]
    data = [
        [
            getattr(country, pk),
            getattr(country, code),
            getattr(country, name),
        ] for country in country_codes
    ]

    assert result.exit_code == 0
    assert result.output == tabulate(data, header, tablefmt='grid') + '\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_load_codes(mock_datetime, mock_sqlite_block_service,
                    cli_runner, route,  sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        with open('iso.csv', 'w') as f:
            f.write('Ukraine,UA\n')
        result = cli_runner.invoke(
          cli,
          [
              'load', 'codes',
              '--path', 'iso.csv'
          ]
        )

        assert result.exit_code == 0
        assert [
                   (iso.id, iso.name, iso.code)
            for iso in sqlite_block_service.iso_country_codes_all()
        ] == [
            (1, 'Ukraine', 'UA'),
        ]


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_load_codes_already_exists(mock_datetime, mock_sqlite_block_service,
                                   cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        with open('iso.csv', 'w') as f:
            f.write('Ukraine,UA\nUkraine,UA\n')
        result = cli_runner.invoke(
          cli,
          [
              'load', 'codes',
              '--path', 'iso.csv'
          ]
        )

        assert result.exit_code == 0
        assert result.output == '1970-01-01T00:00:00Z: row already exists:\nname - Ukraine\ncode - UA\n\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_load_codes_wrong_file(mock_datetime, mock_sqlite_block_service,
                               cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        with open('iso.csv', 'w') as f:
            f.write('Ukraine\n')
        result = cli_runner.invoke(
          cli,
          [
              'load', 'codes',
              '--path', 'iso.csv'
          ]
        )

        assert result.exit_code == 0
        assert result.output == '1970-01-01T00:00:00Z: country code csv file must have two columns\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_load_codes_file_not_found(mock_datetime, mock_sqlite_block_service,
                                   cli_runner, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
          cli,
          [
              'load', 'codes',
              '--path', 'iso.csv'
          ]
        )

        assert result.exit_code == 0
        assert result.output == '1970-01-01T00:00:00Z: No such file or directory\n'


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_codes(mock_datetime, mock_sqlite_block_service,
                    cli_runner, code, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(
      cli,
      [
          'drop', 'codes'
      ]
    )

    assert result.exit_code == 0
    assert sqlite_block_service.iso_country_codes_all() == []


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_drop_all_command(mock_datetime, mock_sqlite_block_service,
                          cli_runner, code, countries, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(
      cli,
      [
          'drop', 'all'
      ]
    )

    assert result.exit_code == 0
    assert sqlite_block_service.get_all_routes() == []
    assert sqlite_block_service.iso_country_codes_all() == []
    assert sqlite_block_service.get_all_countries() == []


@patch('block.SqliteBlockService')
@patch('fail_warn.datetime')
def test_routes_command(mock_datetime, mock_sqlite_block_service,
                          cli_runner, route, sqlite_block_service):
    mock_datetime.datetime.utcnow.return_value = '1970-01-01T00:00:00Z'
    mock_sqlite_block_service.return_value = sqlite_block_service

    result = cli_runner.invoke(
      cli,
      [
          'drop', 'routes'
      ]
    )

    assert result.exit_code == 0
    assert sqlite_block_service.get_all_routes() == []
