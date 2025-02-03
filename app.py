from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS 
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from datetime import datetime
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from datetime import timedelta



load_dotenv()

app = Flask(__name__, static_folder='../dist', static_url_path='')

CORS(
    app,
    resources={r"/api/*": {"origins": ["http://localhost:5173", "https://GreenMakerLab.onrender.com"]}},
    supports_credentials=True,
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

app.config['JWT_SECRET_KEY'] = secrets.token_hex(16)
jwt = JWTManager(app)

app.secret_key = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelo de Artigos
class Articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    resume = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)
    doi = db.Column(db.String)
    date = db.Column(db.Date, nullable=False,)
    
# Modelo do Usuario 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Cria o banco de dados e insere o usuário admin (se não existir)
with app.app_context():
    db.create_all()
    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')

    if not admin_username or not admin_password:
        raise ValueError("Credenciais configuradas incorretamente, verifique o .env")

    if not User.query.filter_by(username=admin_username).first():
        admin_user = User(username=admin_username)
        admin_user.set_password(admin_password)
        db.session.add(admin_user)
        db.session.commit()


# Endpoint de login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    # Verifica se o usuário existe e se a senha está correta
    if user and check_password_hash(user.password_hash, password):
        # Cria um token de acesso
        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(hours=1))   
        return jsonify({
            'message': 'Login realizado com sucesso!',
            'access_token': access_token
        }), 200
    else:
        return jsonify({'message': 'Usuário ou senha incorretos.'}), 401

# Endpoint do admin
@app.route('/api/admin', methods=['GET'])
@jwt_required()  
def admin_route():
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, user_id) 

        if not user:
            return jsonify({"message": "Usuário não encontrado!"}), 404

        return jsonify({
            "message": f"Bem-vindo, {user.username}!",
            "data": "Aqui estão os dados do admin..."
        })
    
    except Exception as e:
        print("Erro em /api/admin:", str(e))  
        return jsonify({"message": "Erro interno do servidor"}), 500
    
    
# Endpoint para listar artigos
@app.route('/api/articles', methods=['GET'])
def get_articles():
    articles = Articles.query.all()
    return jsonify([{
        'id': article.id,
        'title': article.title,
        'resume': article.resume,
        'content': article.content,
        'doi': article.doi,
        'date': article.date.isoformat()
    } for article in articles])

# Endpoint para criar um novo artigo
@app.route('/api/articles', methods=['POST'])
@jwt_required()
def create_article():
    data = request.get_json()

    # Validação dos campos obrigatórios
    if not data or 'title' not in data or 'resume' not in data or 'content' not in data or 'date' not in data:
        return jsonify({
            'message': 'Campos obrigatórios faltando!',
            'missing_fields': ['title', 'resume', 'content', 'date']
        }), 400

    try:
        new_article = Articles(
            title=data['title'],
            resume=data['resume'],
            content=data['content'],
            doi=data.get('doi'),
            date=datetime.strptime(data['date'], '%Y-%m-%d').date()
        )
        db.session.add(new_article)
        db.session.commit()
        return jsonify({
            'message': 'Artigo criado com sucesso!',
            'article_id': new_article.id  
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'message': 'Erro interno do servidor',
            'error': str(e)
        }), 500
        
# Endpoint para excluir um artigo
@app.route('/api/articles/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_article(id):
    article = Articles.query.get_or_404(id)
    db.session.delete(article)
    db.session.commit()
    return jsonify({'message': 'Artigo deletado com sucesso!'})


@app.route('/')
def serve_home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/team')
def team():
    return send_from_directory(app.static_folder, 'team.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')
if __name__ == '__main__':
    app.run(debug=True)
