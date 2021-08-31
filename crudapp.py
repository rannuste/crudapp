from typing import Callable
from flask import Flask, request, jsonify, make_response
from flask_bcrypt import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import jwt


# prevention of warnings 'Unresolved attribute reference 'name' for class SQLAlchemy'
class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    String: Callable
    Integer: Callable
    Boolean: Callable
    DateTime: Callable


# create app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crudtest.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = MySQLAlchemy(app)


# db table model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=True, unique=True)
    pw_hash = db.Column(db.String(128), nullable=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(150))
    is_active = db.Column(db.Boolean, nullable=True)
    last_login = db.Column(db.DateTime, default=datetime.utcnow())
    is_superuser = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, first_name, last_name, is_active, is_superuser=False):
        self.username = username
        self.pw_hash = bcrypt.generate_password_hash(password)
        self.first_name = first_name
        self.last_name = last_name
        self.is_active = is_active
        self.is_superuser = is_superuser

    def __repr__(self):
        return '<Model %r>' % self.id
        # return f"{self.id}"

    # to make response
    def get_serialize_object(self):
        return {'id': self.id,
                'username': self.username,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'is_active': self.is_active,
                'last_login': self.last_login.strftime("%m/%d/%Y, %H:%M:%S"),
                'is_superuser': self.is_superuser}

    def encode_auth_token(self, user_id):
        try:
            payload = {
                'exp': datetime.utcnow() + datetime.timedelta(days=0, second=5),
                'iat': datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='H256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please try log in again'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please try log in again'


# deserialize json to model object
def deserialize(json_data, user_id=None):
    if user_id is None:
        username = json_data.get(['username'], None)
        password = json_data.get(['password'], None)
        first_name = json_data.get(['first_name'], None)
        last_name = json_data.get(['last_name'], None)
        is_active = json_data.get(['is_active'], None)
        return User(username, password, first_name, last_name, is_active)
    else:
        user = db.session.query.filter_by(id=user_id).first()
        user.password = json_data.get(['password'], None)
        user.username = json_data.get(['username'], None)
        user.first_name = json_data.get(['first_name'], user.first_name)
        user.last_name = json_data.get(['last_name'], user.first_name)
        user.is_active = json_data.get(['is_active'], None)
        return user


@app.route('/api-token-auth/', methods=['POST'])
def user_login():
    data = request.get_json()
    try:
        user = User.query.filter_by(username=data['username']).first()
        if(bcrypt.check_password_hash(user.pw_hash, data['password'])):
            auth_token = user.encode_auth_token(user.id)
            if auth_token:
                return make_response(jsonify(auth_token.decode()))
        else:
            return make_response((jsonify(status='fail')))
    except Exception as e:
        return e


# get db context
@app.route('/api/v1/users/', methods=['GET'])
def get_users():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''

    if auth_token:
        resp = User.decode_auth_token(auth_token)

        if not isinstance(resp, str):
            users = db.session.query(User).all()
            s = []
            for i in users:
                s.append(i.get_serialize_object())

            return make_response(jsonify(s))

    return make_response(jsonify(status='fail'))


# get user(id) context
@app.route('/api/v1/users/<id>/', methods=['GET'])
def get_user(id):
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''

    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            db_user_context = User.query.filter_by(id=id).first().get_serialize_object()
            return make_response(jsonify(db_user_context))

    return make_response(jsonify(status='fail'))


# add new user
@app.route('/api/v1/users/', methods=['POST'])
def register_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user:
        try:
            new_user = deserialize(data)
            db.session.add(new_user)
            db.session.commit()
            db_user_context = User.query.filter_by(username=data['username']).first().get_serialize_object()
            return make_response(jsonify(db_user_context))
        except Exception as e:
            return make_response(jsonify(status='fail'))

    return make_response(jsonify(status='fail'))


# update user(id) data
@app.route('/api/v1/users/<id>/', methods=['PUT', 'PATCH'])
def update_user(id):
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''

    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            data = request.get_json()
            user = deserialize(data, id)
            db.session.add(user)
            db.session.commit()
            db_user_context = User.query.filter_by(id=id).first().get_serialize_object()
            return make_response(jsonify(db_user_context))
        else:
            return make_response(jsonify(status='fail'))

    return make_response(jsonify(status='fail'))


@app.route('/api/v1/users/<id>/', methods=['DELETE'])
def remove_user(id):
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''

    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.query.filter_by(id=id).first()
            db.session.delete(user)
            db.session.commit()
        else:
            return make_response(jsonify(status='fail'))

    return make_response(jsonify(status='fail'))


if __name__ == "__main__":
    app.run(debug=True)
