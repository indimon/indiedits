from decouple import config

DATABASE_URI = config('postgresql://postgres:password@igame-instance.cj3l9swcgrzl.us-east-1.rds.amazonaws.com/igame_db')


class Config(object):
    # needs work