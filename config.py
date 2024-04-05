class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    SECRET_KEY = 'csc400'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = 'OwlGoSCSU@gmail.com'
    MAIL_PASSWORD = 'rbjb dwxk lqly smlz'
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEFAULT_SENDER = ('ThriftyOwl', 'OwlGoSCSU@gmail.com')