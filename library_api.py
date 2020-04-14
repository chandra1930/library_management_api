from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'whaddup'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/mehedees/PycharmProjects/library_api/library.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    isbn = db.Column(db.String(80), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)


def init_project():
    '''
    Creates necessary DB tables and create superuser
    :return: Result with superuser username and password.
    '''
    try:
        db.create_all()
        super_user = User(
            public_id=str(uuid.uuid4()),
            username='su',
            password=generate_password_hash('123456'),
            is_admin=True
        )
        db.session.add(super_user)
        db.session.commit()
        return 'DB setup and superuser creation successful!\nusername:su\npassword:123456'
    except Exception as e:
        return 'DB setup and superuser creation failed!'



def login_required(func):
    '''
    decorator to check if user is logged in
    :param func:
    :return: logged in user or proper error response.
    '''
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({
                'message': 'Token required!'
            }), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']
            ).first()
        except jwt.InvalidTokenError as e:
            return jsonify({
                'message': e.args[0]
            }), 500

        return func(current_user, *args, **kwargs)

    return decorated


@app.route('/create_user', methods=['POST'])
@login_required
def create_user(current_user):
    '''
    creates user with username, password. public_key is auto-generated and is_admin is by default False.
    :param current_user:
    :return: Result response
    '''
    if not current_user.is_admin:
        return jsonify({
            'message': 'Permission denied!'
        }), 401
    data = None
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({
            'message': 'Username & Password is required'
        }), 400
    else:
        try:
            is_existing = User.query.filter_by(
                username=data.get('username')
            ).first()

            if is_existing:
                return jsonify({
                    'message': 'Username exists!'
                }), 400

            new_user = User(
                public_id=str(uuid.uuid4()),
                username=data['username'],
                password=generate_password_hash(data['password']),
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            return jsonify({
                'message': 'Something went wrong, please try again!'
            }), 500

        return jsonify({
            'message': 'Successfully created user'
        }), 201


@app.route('/login', methods=['POST'])
def login():
    '''
    logs in user with username and password.
    jwt token is created with public_id, expiration time=1 hour, app secret key.
    :return: token
    '''
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Invalid credentials', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Invalid credentials', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'])

        return jsonify({
            'token': token.decode('UTF-8')
        }), 200

    return make_response('Invalid credentials', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})


@app.route('/users', methods=['GET'])
@login_required
def users(current_user):
    '''
    :param current_user:
    :return:list of users(username, public_id and is_admin)
    '''
    if not current_user.is_admin:
        return jsonify({
            'message': 'Permission denied!'
        }), 401

    users = User.query.all()

    data = []

    for user in users:
        data.append(dict(
            public_id=user.public_id,
            username=user.username,
            is_admin=user.is_admin
        ))

    return jsonify({'users': data}), 200


@app.route('/promote/<public_id>', methods=['GET'])
@login_required
def promote(current_user, public_id):
    '''
    Promote user to admin
    :param current_user:
    :param public_id:
    :return: Result response
    '''
    if not current_user.is_admin:
        return jsonify({
            'message': 'Permission denied!'
        }), 401

    user = User.query.filter_by(
        public_id=public_id
    ).first()

    if not user:
        return jsonify({
            'message': 'Invalid user!'
        }), 400

    user.is_admin = True
    db.session.commit()

    return jsonify({
        'message': '{} promoted to admin!'.format(user.username)
    }), 200


@app.route('/book/add', methods=['POST'])
@login_required
def add_book(current_user):
    '''
    add new book with isbn, name, author name.
    :param current_user:
    :return: result response
    '''
    if not current_user.is_admin:
        return jsonify({
            'message': 'Permission denied!'
        }), 401

    data = request.get_json()

    isbn = data.get('isbn')
    name = data.get('name')
    author = data.get('author')

    if not isbn or not name or not author:
        return jsonify({
            'message': 'ISBN, Book Name & Author Name are required!'
        }), 400

    try:
        is_duplicate = Book.query.filter_by(
            isbn=isbn
        ).first()

        if is_duplicate:
            return jsonify({
                'message': 'This ISBN already exists!'
            }), 400

        new_book = Book(
            isbn=isbn,
            name=name,
            author=author
        )

        db.session.add(new_book)
        db.session.commit()

        return jsonify({
            'message': 'Book added successfully!'
        }), 201
    except Exception as e:
        return jsonify({
            'message': 'Something went wrong!'
        }), 500


@app.route('/book/<isbn>/edit', methods=['POST'])
@login_required
def edit_book(current_user, isbn):
    '''
    edit book info using isbn.
    :param current_user:
    :param isbn:
    :return: result response
    '''
    if not current_user.is_admin:
        return jsonify({
            'message': 'Permission denied!'
        }), 401

    data = request.get_json()

    book = Book.query.filter_by(
        isbn=isbn
    ).first()

    if not book:
        return jsonify({
            'message': 'Couldn\'t find book!'
        }), 400

    try:
        book.isbn = data.get('isbn', book.isbn)
        book.name = data.get('name', book.name)
        book.author = data.get('author', book.author)

        if db.session.dirty:
            db.session.commit()
            return jsonify({
                'message': 'Book info updated successfully!'
            }), 200
        else:
            return jsonify({
                'message': 'No changes made!'
            }), 400
    except Exception as e:
        return jsonify({
            'message': 'Something went wrong!'
        }), 500


@app.route('/book/<isbn>/delete', methods=['DELETE'])
@login_required
def delete_book(current_user, isbn):
    '''
    delete book using isbn
    :param current_user:
    :param isbn:
    :return: result response
    '''
    if not current_user.is_admin:
        return jsonify({
            'message': 'Permission denied!'
        }), 401

    book = Book.query.filter_by(
        isbn=isbn
    ).first()

    if not book:
        return jsonify({
            'message': 'Couldn\'t find book!'
        }), 400

    try:
        db.session.delete(book)
        db.session.commit()

        return jsonify({
            'message': 'Book deleted successfully!'
        }), 200
    except Exception as e:
        return jsonify({
            'message': 'Something went wrong!'
        }), 500


@app.route('/books', methods=['GET'])
@login_required
def books(current_user):
    '''
    :param current_user:
    :return: list of books(isbn, name, author name)
    '''
    books = Book.query.all()

    data = []

    for book in books:
        data.append(dict(
            isbn=book.isbn,
            name=book.name,
            author=book.author
        ))

    return jsonify({'books': data}), 200


@app.route('/books', methods=['POST'])
@login_required
def search_books(current_user):
    '''
    search for book using partial string search
    :param current_user:
    :return: list of books
    '''
    data = request.get_json()

    search_name = data.get('name')

    try:
        books = Book.query.filter(
            Book.name.contains(search_name)
        ).all()
    except Exception as e:
        return jsonify({
            'message': 'Something went wrong!'
        }), 500

    data = []

    for book in books:
        data.append(dict(
            isbn=book.isbn,
            name=book.name,
            author=book.author
        ))

    return jsonify({'books': data}), 200


if __name__ == '__main__':
    app.run()
