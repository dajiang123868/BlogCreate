# -*- coding: utf-8 -*-

from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required,current_user

from . import auth
from ..models import User
from .. import db
from .forms import LoginForm, RegistrationForm
from ..email import send_email


# @auth.before_app_request
# def before_request():
#     if current_user.is_authenticated \
#             and not current_user.confirmed \
#             and request.endpoint \
#             and request.blueprint != 'auth' \
#             and request.endpoint != 'static':
#         return redirect(url_for('auth.unconfirmed'))
#
#
# @auth.route('/unconfirmed')
# def unconfirmed():
#     if current_user.is_anonymous or current_user.confirmed:
#         return redirect(url_for('main.index'))
#     return render_template('auth/unconfirmed.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # 判断验证规则通过
    if form.validate_on_submit():
        # 查询用户
        user = User.query.filter_by(email=form.email.data.lower()).first()
        # 如果用户存在，并且密码正确
        if user is not None and user.verify_password(form.password.data):
            # 在会话中标记用户已经登录装态
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index',user=user)
            return redirect(next)
        flash('密码或用户名错误')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('你已退出登录！')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('已发送邮件到您的邮箱')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('请验证您的邮箱谢谢！')
    else:
        flash('验证过期')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('一个新的验证链接已发送到您的邮箱！')
    return redirect(url_for('main.index'))

