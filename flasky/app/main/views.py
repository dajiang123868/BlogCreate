# -*- coding: utf-8 -*-

from flask import render_template, session, redirect, url_for, current_app
from .. import db
from ..models import User,Permission
from ..email import send_email
from . import main
from .forms import NameForm
from ..decorators import admin_required, permission_required
from flask_login import login_user, logout_user, login_required,current_user


@main.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@main.route('/list.html', methods=['GET', 'POST'])
def blog_list():
    return render_template('list.html')

@main.route('/admin')
@login_required
@admin_required
def for_admins_only():
 return "For administrators!"


@main.route('/moderator')
@login_required
@permission_required(Permission.COMMENT)
def for_moderators_only():
 return "For comment moderators!"