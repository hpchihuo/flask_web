# _*_ coding:utf-8 _*_
from flask import render_template, redirect, request, url_for, flash 
from flask_login import login_user
from ..models import User 
from .forms import LoginForm
from . import auth
from flask_login import logout_user, login_required
from ..email import send_email
from flask_login import current_user



@auth.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.Validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET','POST'])
def register():
    form = Registrationform()
    if form.Validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm  your Account', 'auth/email/confirm', user=user, token = token)
        flash('A confirm email has been sent to your email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirmed(token):
        flash('You have comfirmed your acount. Thanks')
    else:
        flash('The confirmation link is invalid or has expired')
    return redirect(url_for('main.index'))

#在登录前确认是否经过邮箱验证
@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
            and request.endpoint[:5] != 'auth.':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

#重新发送邮件
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm  your Account', 'auth/email/confirm', user=current_user, token = token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))
