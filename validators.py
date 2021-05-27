import ipaddress


def validate_ip(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError('cannot convert to ip address')


def validate_subnet(value):
    try:
        return ipaddress.ip_network(value)
    except ValueError:
        raise ValidationError('cannot convert to network address')


def validate_nginx_phrase(value):
    phrases = {'all'}
    if value not in phrases:
        raise ValidationError('not an nginx phrase')

    return value


def validate_address(address, validators):
    error_messages = []

    for validator in validators:
        try:
            return str(validator(address))
        except ValidationError as e:
            error_messages.append(e.message)

    raise ValidationError(
        '\n'.join(error_messages)
    )


class ValidationError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message
