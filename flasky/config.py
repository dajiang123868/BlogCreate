# -*- coding: utf-8 -*-
import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """
    默认公用参数
    """
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.qq.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '25'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in \
        ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME','1661891049@qq.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD','ufbwbqgrfzhzehgc')
    FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
    FLASKY_MAIL_SENDER = 'Flasky Admin <1661891049@qq.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN','1661891049@qq.com')
    # 将其设为 True时，每次请求结束后都会自动提交数据库中的变动
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    """
    开发环境测试
    """
    DEBUG = True
    # mysql://username:password@hostname/database
    # 数据库地址
    MYSQL_HOST = os.getenv('MYSQL_HOST','127.0.0.1')
    # 数据库密码
    MYSQL_PWD = os.getenv('MYSQL_PWD','123456')
    # 数据库
    MYSQL_DATABASE = os.getenv('MYSQL_DATABASE','test')
    SQLALCHEMY_DATABASE_URI = 'mysql://root:{0}@{1}/{2}'.format(MYSQL_PWD,MYSQL_HOST,MYSQL_DATABASE)


class TestingConfig(Config):
    TESTING = True
    """
       开发环境测试
       """
    # mysql://username:password@hostname/database
    # 数据库地址
    MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
    # 数据库密码
    MYSQL_PWD = os.getenv('MYSQL_PWD', '123456')
    # 数据库
    MYSQL_DATABASE = os.getenv('MYSQL_DATABASE', 'test')
    SQLALCHEMY_DATABASE_URI = 'mysql://root:{0}@{1}/{2}'.format(MYSQL_PWD, MYSQL_HOST, MYSQL_DATABASE)


class ProductionConfig(Config):
    """
    生产环境配置
    """
    # mysql://username:password@hostname/database
    # 数据库地址
    MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
    # 数据库密码
    MYSQL_PWD = os.getenv('MYSQL_PWD', '123456')
    # 数据库
    MYSQL_DATABASE = os.getenv('MYSQL_DATABASE', 'test')
    SQLALCHEMY_DATABASE_URI = 'mysql://root:{0}@{1}/{2}'.format(MYSQL_PWD, MYSQL_HOST, MYSQL_DATABASE)


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
