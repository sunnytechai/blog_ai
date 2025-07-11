from flask import Flask, request, jsonify, send_from_directory
import jwt
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'blogai.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)

# Models
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    user_type = db.Column(db.String(20), default='user')  # 'user' or 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
# Routes
from flask import session
app.secret_key = 'supersecretkey'  # Change for production
JWT_SECRET = 'jwtsecretkey'  # Change for production
JWT_EXP_DELTA_SECONDS = 3600

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email already registered'}), 400
    user = User(
        username=data.get('username'),
        email=data.get('email'),
        user_type=data.get('user_type', 'user'),
        is_admin=data.get('is_admin', False)
    )
    user.set_password(data.get('password'))
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered', 'id': user.id}), 201

@app.route('/login', methods=['POST'])
def login():
    # Support both form data and JSON
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        payload = {
            'user_id': user.id,
            'is_admin': user.is_admin,
            'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        return jsonify({'message': 'Login successful', 'token': token, 'id': user.id, 'is_admin': user.is_admin})
    return jsonify({'error': 'Invalid credentials'}), 401

# Google OAuth login (stub)
@app.route('/login/google', methods=['POST'])
def login_google():
    # Here you would integrate Flask-Dance or similar for Google OAuth
    # For now, just a stub
    data = request.form
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=data.get('username'), email=email)
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    return jsonify({'message': 'Google login successful', 'id': user.id})

# Admin assign role
@app.route('/users/<int:user_id>/role', methods=['POST'])
def assign_role(user_id):
    if not session.get('is_admin'):
        return jsonify({'error': 'Admin only'}), 403
    user = User.query.get_or_404(user_id)
    user.user_type = request.form.get('user_type', 'user')
    user.is_admin = user.user_type == 'admin'
    db.session.commit()
    return jsonify({'message': 'Role updated'})

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    header_image = db.Column(db.String(200))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category')
    tags = db.relationship('Tag', secondary=post_tags, backref=db.backref('posts'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User')
    is_private = db.Column(db.Boolean, default=True)
    scheduled = db.Column(db.Boolean, default=False)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    post = db.relationship('Post', backref=db.backref('images'))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    post = db.relationship('Post', backref=db.backref('comments'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User')
    is_verified = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))  # For replies
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]))

class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class CommentHeart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Ensure all tables are created on startup
with app.app_context():
    db.create_all()

# ...existing code...
@app.route('/')
def home():
    return jsonify({'message': 'Blog API Home'})

# CRUD for posts
@app.route('/posts', methods=['GET', 'POST'])
def posts():
    if request.method == 'GET':
        posts = Post.query.all()
        return jsonify([
            {
                'id': p.id,
                'title': p.title,
                'content': p.content,
                'header_image': p.header_image,
                'category': p.category.name if p.category else None,
                'tags': [t.name for t in p.tags],
                'author': p.author.username if p.author else None,
                'is_private': p.is_private,
                'scheduled': p.scheduled
            } for p in posts
        ])
    else:
        # Support both form data and JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        post = Post(
            title=data.get('title'),
            content=data.get('content'),
            author_id=data.get('author_id'),
            category_id=data.get('category_id'),
            is_private=data.get('is_private', True),
            scheduled=data.get('scheduled', False)
        )
        db.session.add(post)
        db.session.commit()
        return jsonify({'id': post.id}), 201

@app.route('/posts/<int:post_id>', methods=['GET', 'PUT', 'DELETE'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'GET':
        return jsonify({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'header_image': post.header_image,
            'category': post.category.name if post.category else None,
            'tags': [t.name for t in post.tags],
            'author': post.author.username if post.author else None,
            'is_private': post.is_private,
            'scheduled': post.scheduled
        })
    elif request.method == 'PUT':
        data = request.form
        post.title = data.get('title', post.title)
        post.content = data.get('content', post.content)
        post.is_private = data.get('is_private', post.is_private)
        post.scheduled = data.get('scheduled', post.scheduled)
        db.session.commit()
        return jsonify({'message': 'Post updated'})
    else:
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted'})

# Image upload
@app.route('/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    file = request.files['image']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    image = Image(filename=filename, post_id=request.form.get('post_id'))
    db.session.add(image)
    db.session.commit()
    return jsonify({'filename': filename}), 201

@app.route('/uploads/<filename>')
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


from functools import wraps
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user_id = data['user_id']
            request.is_admin = data['is_admin']
        except Exception as e:
            return jsonify({'error': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

# CRUD for comments (JWT required)
@app.route('/comments', methods=['POST'])
@token_required
def add_comment():
    # Support both form data and JSON, robustly handle types
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    content = data.get('content')
    post_id = data.get('post_id')
    parent_id = data.get('parent_id')

    # Convert post_id and parent_id to int if present
    try:
        post_id = int(post_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'post_id is required and must be an integer'}), 400
    if parent_id is not None and parent_id != '':
        try:
            parent_id = int(parent_id)
        except (TypeError, ValueError):
            return jsonify({'error': 'parent_id must be an integer'}), 400
    else:
        parent_id = None

    if not content:
        return jsonify({'error': 'content is required'}), 400

    comment = Comment(
        content=content,
        post_id=post_id,
        author_id=request.user_id,
        is_verified=False,
        parent_id=parent_id
    )
    db.session.add(comment)
    db.session.commit()
    return jsonify({'id': comment.id}), 201

@app.route('/comments/<int:comment_id>/like', methods=['POST'])
@token_required
def like_comment(comment_id):
    like = CommentLike(comment_id=comment_id, user_id=request.user_id)
    db.session.add(like)
    db.session.commit()
    return jsonify({'message': 'Comment liked'})

@app.route('/comments/<int:comment_id>/heart', methods=['POST'])
@token_required
def heart_comment(comment_id):
    heart = CommentHeart(comment_id=comment_id, user_id=request.user_id)
    db.session.add(heart)
    db.session.commit()
    return jsonify({'message': 'Comment hearted'})

@app.route('/comments/<int:post_id>', methods=['GET'])
def get_comments(post_id):
    comments = Comment.query.filter_by(post_id=post_id, parent_id=None).all()
    def serialize_comment(comment):
        return {
            'id': comment.id,
            'content': comment.content,
            'author': comment.author.username if comment.author else None,
            'is_verified': comment.is_verified,
            'likes': CommentLike.query.filter_by(comment_id=comment.id).count(),
            'hearts': CommentHeart.query.filter_by(comment_id=comment.id).count(),
            'replies': [serialize_comment(reply) for reply in comment.replies]
        }
    return jsonify([serialize_comment(c) for c in comments])

# CRUD for categories
@app.route('/categories', methods=['GET', 'POST'])
def categories():
    if request.method == 'GET':
        cats = Category.query.all()
        return jsonify([{'id': c.id, 'name': c.name} for c in cats])
    else:
        # Support both form data and JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        cat = Category(name=data.get('name'))
        db.session.add(cat)
        db.session.commit()
        return jsonify({'id': cat.id}), 201

# CRUD for tags
@app.route('/tags', methods=['GET', 'POST'])
def tags():
    if request.method == 'GET':
        tags = Tag.query.all()
        return jsonify([{'id': t.id, 'name': t.name} for t in tags])
    else:
        data = request.form
        tag = Tag(name=data.get('name'))
        db.session.add(tag)
        db.session.commit()
        return jsonify({'id': tag.id}), 201

# Like and heart
@app.route('/posts/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    user_id = request.form.get('user_id')
    like = Like(post_id=post_id, user_id=user_id)
    db.session.add(like)
    db.session.commit()
    return jsonify({'message': 'Post liked'})

@app.route('/posts/<int:post_id>/heart', methods=['POST'])
def heart_post(post_id):
    user_id = request.form.get('user_id')
    heart = Heart(post_id=post_id, user_id=user_id)
    db.session.add(heart)
    db.session.commit()
    return jsonify({'message': 'Post hearted'})

# Admin approve post
@app.route('/posts/<int:post_id>/approve', methods=['POST'])
def approve_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.is_private = False
    db.session.commit()
    return jsonify({'message': 'Post approved'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
