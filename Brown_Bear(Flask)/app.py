from re import template
from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators  import DataRequired

comments = ["Great Work!"]

app = Flask(__name__)
app.config["SECRET_KEY"] = "my_secret"


class CommentForm(FlaskForm):
    comment = StringField("Recommendations?", validators=[DataRequired()])
    submit = SubmitField("Submit")


@app.route('/', methods=["GET", "POST"])
def index():
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        new_comment = comment_form.comment.data
        comments.append(new_comment)
    return render_template('index_main.html', template_comments=comments, template_form=comment_form)


@app.route('/aboutme')
def about():
    return render_template('aboutme.html')


if __name__ == "__main__":
    app.run()