import environ

env = environ.Env()

DATABASES = {
    'default': env.db(
        default='sqlite:///db.sqlite3',
    )
}
