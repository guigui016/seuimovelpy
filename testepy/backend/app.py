from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import re
import jwt
import datetime
import bcrypt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_super_segura_aqui'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600  # Cache por 1 hora

# CORS para dev/local e produção
CORS(app, resources={r"/api/*": {"origins": "*"}})

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'imobiliaria'
}

def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and " " in auth_header:
            token = auth_header.split(" ")[1]
        if not token:
            return jsonify({'status': 'error', 'message': 'Token de acesso faltando'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, nome, email, tipo_usuario FROM usuarios WHERE id = %s", (data['user_id'],))
            current_user = cursor.fetchone()
            if not current_user:
                return jsonify({'status': 'error', 'message': 'Usuário não existe'}), 401
            return f(current_user, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 'error', 'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 'error', 'message': 'Token inválido'}), 401
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Erro na autenticação: {e}'}), 401
        finally:
            if 'conn' in locals() and conn.is_connected():
                cursor.close()
                conn.close()
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email e senha são obrigatórios'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user and check_password(password, user['senha']):
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'status': 'success',
                'token': token,
                'user': {
                    'id': user['id'],
                    'nome': user['nome'],
                    'email': user['email'],
                    'tipo_usuario': user['tipo_usuario']
                }
            }), 200
        
        return jsonify({'status': 'error', 'message': 'Credenciais inválidas'}), 401
    except Error as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/usuarios', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['nome', 'email', 'password', 'tipo_usuario']
        if not all(field in data for field in required_fields):
            return jsonify({'status': 'error', 'message': 'Todos os campos são obrigatórios'}), 400
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', data['email']):
            return jsonify({'status': 'error', 'message': 'Email inválido'}), 400
        if len(data['password']) < 6:
            return jsonify({'status': 'error', 'message': 'Senha deve ter pelo menos 6 caracteres'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM usuarios WHERE email = %s", (data['email'],))
        if cursor.fetchone():
            return jsonify({'status': 'error', 'message': 'Email já cadastrado'}), 400
            
        hashed_password = hash_password(data['password'])
        cursor.execute("""
            INSERT INTO usuarios (nome, email, senha, tipo_usuario)
            VALUES (%s, %s, %s, %s)
        """, (data['nome'], data['email'], hashed_password, data['tipo_usuario']))
        conn.commit()
        user_id = cursor.lastrowid
        
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'status': 'success',
            'message': 'Usuário registrado com sucesso',
            'token': token,
            'user': {
                'id': user_id,
                'nome': data['nome'],
                'email': data['email'],
                'tipo_usuario': data['tipo_usuario']
            }
        }), 201
    except Error as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/anuncios', methods=['GET', 'POST'])
@token_required
def anuncios(current_user):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if request.method == 'GET':
            cursor.execute("""
                SELECT a.*, u.nome as anunciante
                FROM anuncios a
                JOIN usuarios u ON a.usuario_id = u.id
                WHERE a.status != 'Vendido'
            """)
            anuncios = cursor.fetchall()
            return jsonify({'status': 'success', 'data': anuncios})
        elif request.method == 'POST':
            data = request.get_json()
            required_fields = ['categoria', 'endereco', 'metragem', 'comodos', 'tipo', 'preco']
            if not all(field in data for field in required_fields):
                return jsonify({'status': 'error', 'message': 'Campos obrigatórios faltando'}), 400
            if data.get('imgURL') and len(data['imgURL']) > 3_000_000:
                return jsonify({'status': 'error', 'message': 'Imagem muito grande'}), 400
                
            cursor.execute("""
                INSERT INTO anuncios (
                    categoria, endereco, metragem, comodos, tipo, preco, status,
                    observacoes, imgURL, usuario_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data['categoria'], data['endereco'], data['metragem'],
                data['comodos'], data['tipo'], data['preco'],
                data.get('status', 'À venda'), data.get('observacoes'),
                data.get('imgURL'), current_user['id']
            ))
            conn.commit()
            anuncio_id = cursor.lastrowid
            return jsonify({
                'status': 'success',
                'message': 'Anúncio criado!',
                'id': anuncio_id
            }), 201
    except Error as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/anuncios/<int:id>', methods=['PUT', 'DELETE'])
@token_required
def anuncio_by_id(current_user, id):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        if request.method == 'PUT':
            data = request.get_json()
            cursor.execute("""
                UPDATE anuncios SET
                    categoria = %s, endereco = %s, metragem = %s,
                    comodos = %s, tipo = %s, preco = %s,
                    status = %s, observacoes = %s, imgURL = %s
                WHERE id = %s AND usuario_id = %s
            """, (
                data['categoria'], data['endereco'], data['metragem'],
                data['comodos'], data['tipo'], data['preco'],
                data.get('status'), data.get('observacoes'), data.get('imgURL'),
                id, current_user['id']
            ))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({'status': 'error', 'message': 'Anúncio não encontrado ou não autorizado'}), 404
            return jsonify({'status': 'success', 'message': 'Anúncio atualizado!'})
        elif request.method == 'DELETE':
            cursor.execute("DELETE FROM anuncios WHERE id = %s AND usuario_id = %s", (id, current_user['id']))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({'status': 'error', 'message': 'Anúncio não encontrado ou não autorizado'}), 404
            return jsonify({'status': 'success', 'message': 'Anúncio excluído!'})
    except Error as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/meus-anuncios', methods=['GET'])
@token_required
def meus_anuncios(current_user):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM anuncios WHERE usuario_id = %s", (current_user['id'],))
        anuncios = cursor.fetchall()
        return jsonify({'status': 'success', 'data': anuncios})
    except Error as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/api/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({'status': 'success', 'data': current_user})

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({'status': 'success', 'message': 'API está funcionando'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)