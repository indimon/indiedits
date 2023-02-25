from flask import Flask, Response, render_template, request, jsonify
import json
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import InputRequired, length

app = Flask(__name__)
app.config['SECRET_KEY'] = 'TheSecretKeyForTeam9'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'postgresql://postgres:password@igame-instance.cj3l9swcgrzl.us-east-1.rds.amazonaws.com/igame_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class SearchForm(FlaskForm):
    game = StringField('List a game you like', validators=[InputRequired(), length(max=40)], render_kw={"placeholder": "video game name"})


class VideoGame(db.Model):
    __tablename__ = 'games'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True, nullable=False)

    def as_dict(self):
        return {'name': self.name}


@app.route('/game')
def gamedic():
    res = VideoGame.query.all()
    list_games = [r.as_dict() for r in res]
    return jsonify(list_games)


@app.route('/')
def index():
    form = SearchForm(request.form)
    return render_template('search.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)