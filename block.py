#!/home/user/work/projects/console_geo_block/.env/bin/python3
import csv
import click


import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tabulate import tabulate
from jinja2 import Environment, PackageLoader, select_autoescape
from services.geo_block import (
    SqliteBlockService,
)
from services.models import IPAccessEnum
from services.geo_block import (
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
from fail_warn import command_fail
from settings import (
    DATABASE_URL,
    NGINX_COUNTRY_VARIABLE,
    MODULE_NAME,
    TEMPLATES_FOLDER,
)


@click.group(help='CLI block')
@click.pass_context
def cli(ctx):
    engine = create_engine(DATABASE_URL)
    session = sessionmaker(
        bind=engine,
        autoflush=True,
        autocommit=True,
    )()
    ctx.obj = SqliteBlockService(session)

    @ctx.call_on_close
    def on_close():  # pylint: disable=unused-variable
        session.close()


@cli.group(name='add', help='Add things to manage them')
def add():
    pass


@cli.group(name='drop', help='Drop things')
def drop():
    pass


@cli.group(name='show', help='Show info')
def show():
    pass


@cli.group(name='render', help='Render rules')
def render_group():
    pass


@cli.group(name='alter', help='Alter things')
def alter():
    pass


@cli.group(name='load', help='Load')
def load():
    pass


@add.command(name='route', help='Add new route')
@click.option('--label', type=str, required=True, help='Route label')
@click.option('--default', type=bool, required=True,
              help='Block countries by default (y/n)')
@click.pass_obj
def add_route(service, label, default):
    try:
        service.create_route(label, default)
    except ServiceIntegrityError as e:
        command_fail(e.message)


@drop.command(name='route', help='Drop a route')
@click.option('--label', type=str, required=True,
              help='Route label')
@click.pass_obj
def drop_route(service, label):
    try:
        service.drop_route(label)
    except ServiceNotFoundError as e:
        command_fail(e.message)


@add.command(name='country', help='Add country to route')
@click.option('--label', type=str, required=True,
              help='Route label for which you want to add a country')
@click.option('--code', type=str, required=True, help='ISO country code')
@click.option(
    '--is_blocked',
    type=bool,
    required=True,
    help='Block/unblock country (y/n)',
)
@click.pass_obj
def add_country(service, label, code, is_blocked):
    try:
        service.create_routes_country(
            label,
            code.upper(),
            is_blocked,
        )
    except ServiceNotFoundError as e:
        command_fail(e.message)
    except ServiceIntegrityError as e:
        command_fail(e.message)


@drop.command(name='country', help='Drop country assigned route')
@click.option('--label', type=str, required=True, help='Route label')
@click.option('--code', type=str, required=True, help='ISO country code')
@click.pass_obj
def drop_country(service, label, code):
    try:
        service.drop_route_country(label, code.upper())
    except ServiceNotFoundError as e:
        command_fail(e.message)


@show.command(name='routes', help='Show all routes')
@click.pass_obj
def show_routes(service):
    route_objs = service.get_all_routes()
    pk, label, block_by_default = 'id', 'label', 'block_by_default'
    header = [pk, label, block_by_default]
    data = [
        [
            getattr(route, pk),
            getattr(route, label),
            getattr(route, block_by_default),
        ] for route in route_objs
    ]
    click.echo(tabulate(data, header, tablefmt='grid'))


@show.command(name='countries', help='Show all countries info')
@click.pass_obj
def show_countries(service):
    country_objs = service.get_all_countries()
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
    click.echo(tabulate(data, header, tablefmt='grid'))


@show.command(name='route', help='Show route info')
@click.option('--label', type=str, required=True, help='Route label')
@click.pass_obj
def show_route_info(service, label):
    route = service.get_route_by_label(label)
    if not route:
        command_fail(
            'route not found'
        )
    click.echo(
        'route info:\nid: {}\nlabel: {}\nblock by default: {}'.format(
            route.id,
            route.label,
            route.block_by_default,
        )
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
    click.echo(tabulate(data, header, tablefmt='grid'))


def render(template_name, **kwargs):
    env = Environment(
        loader=PackageLoader(MODULE_NAME, TEMPLATES_FOLDER),
        autoescape=select_autoescape(['html', 'xml']),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    return template.render(**kwargs)


@render_group.command(name='geo', help='Render countries map template and save to file')
@click.option('--output', type=click.Path(), required=True,
              help='Path to write countries map')
@click.pass_obj
def render_geo(service, output):
    route_objs = service.get_all_routes()

    try:
        with open(output, 'w') as file:
            file.write(
                render(
                    'country_maps.dat',
                    nginx_country_variable=NGINX_COUNTRY_VARIABLE,
                    routes=route_objs,
                )
            )
    except (
            FileNotFoundError,
            IsADirectoryError,
            NotADirectoryError,
    ) as e:
        command_fail(e.strerror)


@render_group.command(name='ip', help='Render IP map template and save to file')
@click.option('--output', type=click.Path(), required=True,
              help='Path to write IP map')
@click.pass_obj
def render_ip(service, output):
    ip_access_control = service.get_ip_access_controls()

    try:
        with open(output, 'w') as file:
            file.write(
                render(
                    'ip_maps.dat',
                    ip_access_control=ip_access_control,
                )
            )
    except (
            FileNotFoundError,
            IsADirectoryError,
            NotADirectoryError,
    ) as e:
        command_fail(e.strerror)


@add.command(name='ip', help='Add IP to access control list')
@click.option(
    '--access',
    type=click.Choice(
        tuple(IPAccessEnum.__members__)
    ),
    required=True,
    help='Access level for IP',
)
@click.option('--ip', type=str, required=True,
              help='Can be [ip|subnet|"all"]')
@click.pass_obj
def add_ip(service, access, ip):
    try:
        ip = validate_address(
            ip,
            [
                validate_ip,
                validate_subnet,
                validate_nginx_phrase,
            ],
        )
    except ValidationError as e:
        command_fail(e.message)

    try:
        service.create_ip_access_control(access, ip)
    except ServiceIntegrityError as e:
        command_fail(e.message)


@drop.command(name='ip', help='Drop IP from access control list(acl)')
@click.option('--pk', type=int, required=True,
              help='IP access control identifier(id)')
@click.pass_obj
def drop_ip(service, pk):
    try:
        service.drop_ip_access_control(pk)
    except ServiceNotFoundError as e:
        command_fail(e.message)


@alter.command(name='ip-access', help='Alter access level for IP')
@click.option('--pk', type=int, required=True,
              help='IP access control identifier(id)')
@click.option(
    '--access',
    type=click.Choice(
        tuple(IPAccessEnum.__members__)
    ),
    required=True,
    help='Access level for IP',
)
@click.pass_obj
def alter_ip_access(service, pk, access):
    try:
        service.change_access_control_access(pk, access)
    except ServiceNotFoundError as e:
        command_fail(e.message)
    except ServiceIntegrityError as e:
        command_fail(e.message)


@alter.command(name='ip-address', help='Alter IP address')
@click.option('--pk', type=int, required=True,
              help='IP access control identifier')
@click.option('--ip', type=str, required=True,
              help='IP access control address can be [ip|subnet|"all"]')
@click.pass_obj
def alter_ip_address(service, pk, ip):
    try:
        ip = validate_address(
            ip,
            [
                validate_ip,
                validate_subnet,
                validate_nginx_phrase,
            ],
        )
    except ValidationError as e:
        command_fail(e.message)

    try:
        service.change_access_control_address(pk, ip)
    except ServiceNotFoundError as e:
        command_fail(e.message)
    except ServiceIntegrityError as e:
        command_fail(e.message)


@show.command(name='acl', help='Show IP access control list')
@click.pass_obj
def show_acl(service):
    ipacls = service.get_ip_access_controls()
    pk, access, address = 'id', 'access', 'address'
    header = [pk, access, address]
    data = [
        [
            getattr(acl, pk),
            getattr(acl, access).value,
            getattr(acl, address),
        ] for acl in ipacls
    ]
    click.echo(tabulate(data, header, tablefmt='grid'))


@drop.command(name='acl', help='Drop IP access control list')
@click.pass_obj
def drop_acl(service):
    service.drop_all_access_control()


@drop.command(name='route-countries', help='Drop all countries related to a given route')
@click.option('--label', type=str, required=True, help='Route label')
@click.pass_obj
def drop_route_countries(service, label):
    try:
        service.drop_route_countries(label)
    except ServiceNotFoundError as e:
        command_fail(e.message)


@alter.command(name='route-default', help='Alter route block by default')
@click.option('--label', type=str, required=True, help='Route label')
@click.option('--default', type=bool,
              required=True, help='Block countries by default (y/n)')
@click.pass_obj
def alter_route_default(service, label, default):
    try:
        service.set_route_block_by_default(label, default)
    except ServiceNotFoundError as e:
        command_fail(e.message)


@show.command(name='codes', help='Show all ISO country codes')
@click.pass_obj
def show_codes(service):
    country_codes = service.iso_country_codes_all()
    pk, name, code = 'id', 'name', 'code'
    header = [pk, name, code]
    data = [
        [
            getattr(country, pk),
            getattr(country, code),
            getattr(country, name),
        ] for country in country_codes
    ]
    click.echo(tabulate(data, header, tablefmt='grid'))


@load.command(name='codes', help='Load ISO country codes data')
@click.option('--path', type=click.Path(), required=True,
              help='Path to csv file')
@click.pass_obj
def load_codes(service, path):
    code_csvindex = 0
    name_csvindex = 1

    try:
        with open(path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                try:
                    service.iso_country_code_add_row(
                        row[code_csvindex],
                        row[name_csvindex],
                    )
                except ServiceIntegrityError as e:
                    command_fail(e.message)
                except IndexError:
                    command_fail(
                        'country code csv file ' \
                        'must have two columns',
                    )

    except (
            FileNotFoundError,
            IsADirectoryError,
            NotADirectoryError,
    ) as e:
        command_fail(e.strerror)


@drop.command(name='codes', help='Drop all ISO country codes data from database')
@click.pass_obj
def drop_codes(service):
    service.iso_country_codes_drop_all()


@drop.command(name='routes', help='Drop all routes')
@click.pass_obj
def drop_routes(service):
    service.drop_routes()


@drop.command(name='all', help='Drop all')
@click.pass_obj
def drop_all(service):
    service.drop_all()


if __name__ == '__main__':  # pragma: nocover
    cli()  # pylint: disable=no-value-for-parameter
