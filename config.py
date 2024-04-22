class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SECRET_KEY = 'csc400'
    MAIL_SERVER = 'smtp.office365.com'
    MAIL_PORT = 587
    MAIL_USERNAME = 'johnjuela@hotmail.com'
    MAIL_PASSWORD = 'hehplkxugcssxesn'
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_DEFAULT_SENDER = ('ThriftySwap', 'johnjuela@hotmail.com')