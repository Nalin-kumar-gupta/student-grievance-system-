from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user, UserMixin, LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from flask_wtf import FlaskForm
from wtforms.validators import Length, EqualTo, DataRequired, Email, ValidationError


db = SQLAlchemy()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///studentapp.db'
app.config['SECRET_KEY'] = 'abdf855db1a2a15facf7d62c'

db.init_app(app)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=50), unique=True, nullable=False)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password = db.Column(db.String(length=50), nullable=False)
    is_staff = db.Column(db.Boolean, default=False)

    @validates('email_address')
    def validate_email(self, key, email):
        if not email.endswith('@pec.edu.in'):
            raise ValueError("Email must end with @pec.edu.in") #Frontend display
        return email
    

class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign In')


class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError("Username already exists!! Please try a different username")

    def validate_email(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError("Email address already exists try logging in!")

    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    email = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password', validators=[Length(min=5, max=30), DataRequired()])
    password2 = PasswordField(label='Confirm password', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    

@app.route("/")
def home_page():
    return render_template("base.html")

@app.route("/users")
def user_list():
    users = db.session.execute(db.select(User).order_by(User.username)).scalars()
    return render_template("userlist.html", users=users)

@app.route("/login", methods=["GET", "POST"])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.password == form.password.data:
            login_user(attempted_user)
            flash(f"Success! You are logged in as: {attempted_user.username}", category='success')
            return redirect(url_for('user_list'))

        else:
            flash("username and password are not match! please try again", category='danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              email_address=form.email.data,
                              password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        return redirect(url_for('user_list'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f"There was an error creating the user - {err_msg}", category="danger")

    return render_template('register.html', form=form)



@app.route("/user/<int:id>") #not working now
def user_detail(id):
    user = db.get_or_404(User, id)
    return render_template("user/detail.html", user=user)



@app.route("/user/<int:id>/delete", methods=["GET", "POST"]) #not working now
def user_delete(id):
    user = db.get_or_404(User, id)

    if request.method == "POST":
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for("user_list"))

    return render_template("user/delete.html", user=user)