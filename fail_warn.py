import datetime


def command_fail(msg):
    warning = '{}: {}'.format(datetime.datetime.utcnow(), msg)
    print(warning)

    raise SystemExit
