from imp import init_builtin
from re import template
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, BooleanField
from wtforms.validators  import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from datetime import datetime


# App Main
app = Flask(__name__)
app.config["SECRET_KEY"] = "my_secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myDB.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


# Models DB
class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_text = db.Column(db.String(100), index=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), index=True, unique=False)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    joined_at = db.Column(db.DateTime(), index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# DB Initialzation
# with app.app_context():
# db.create_all()


# Forms
class CommentForm(FlaskForm):
    comment = StringField("Recommendations?", validators=[DataRequired()])
    submit = SubmitField("Submit")

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[Email(), DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Routes 
@app.route('/', methods=["GET", "POST"])
def index():
    comment_form = CommentForm()
    if 'comment' in request.form:
        db.session.add(Comments(comment_text=request.form['comment']))
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('index_main.html', template_comments=Comments.query.all(), template_form=comment_form)

@app.route('/aboutme')
def about():
    return render_template('aboutme.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegistrationForm(csrf_enabled=False)
    if register_form.validate_on_submit():
        user = User(name=register_form.name.data, username=register_form.username.data, email=register_form.email.data)
        user.set_password(register_form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=register_form)

@app.route('/login', methods=['GET','POST'])
def login():
  login_form = LoginForm(csrf_enabled=False)
  if login_form.validate_on_submit():
    user = User.query.filter_by(email=login_form.email.data).first()
    if user and check_password_hash(user.password_hash, login_form.password.data):
        login_user(user, remember=login_form.remember.data)
        flash("Login Successful!")
        return redirect(url_for('user', _external=True, _scheme='http'))
    else:
        flash("Wrong Email or Password - Please Try Again!")
        return redirect(url_for('login', _external=True, _scheme='http'))
  return render_template('login.html', form=login_form)

@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    return render_template('user.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been Logged out!")
    return redirect(url_for('login'))


first_comment = Comments(comment_text='Great Work!')
db.session.add(first_comment)
# db.session.commit()

if __name__ == "__main__":
    app.run()


