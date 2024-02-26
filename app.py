from flask import Flask, request, jsonify
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from models.user import User

app = Flask(__name__)

app.config['SECRET_KEY'] = "my_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
login_manager = LoginManager()


db.init_app(app)
login_manager.init_app(app)

#View login
login_manager.login_view = 'login'

#Funação de load do user logado
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

#Rota de login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #Metodo de Login
        user = User.query.filter_by(username=username).first()

        #Validações
        if user and user.password == password:
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({f"message": "Login Válido"})
        else:
            return jsonify({"message": "Dados não conferem"})
        
    return jsonify({"message": "Credenciais Inválidas"}), 400


@app.route('/user', methods=['POST'])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({"message":"Usuário já cadastrado"})
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
        return jsonify({"message": "Cadastro realizado com sucesso"})
                    
    return jsonify({"message": "Credenciais Inválidas"}), 400


#Rota de Logout
@app.route('/logout', methods=['GET'])
@login_required
def user_logout():
    logout_user()
    return jsonify({"message":"Logout realizado com sucesso"})


#Rota Leitura de todos os usuários
@app.route('/user', methods=['GET'])
@login_required
def read_users():
    users = User.query.all()
    # total_users = {"Total": len(users)}
    user_list = [{"ID": user.id, "Chave": user.password,"Nome": user.username} for user in users]
    return jsonify(user_list)


#Rota de Leitura de Usuários por ID
@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    if user:
        return {"Nome": user.username}
    return jsonify({"message": "usuário não encontrado"}), 404

#Rota de Atualização de Usuários por ID
@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)
    if user and data.get("password"):
       user.password = data.get("password")
       db.session.commit()
       return {"Nome": user.username, "Senha": user.password}
    else:
        return jsonify({"message": "usuário não encontrado"}), 404
    
#Rota de Remoção de Usuários
@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)
    if not user:
         return jsonify({"message": "usuário não encontrado"}), 404
    else:
        if user.id != current_user.id:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": f"Usuário: {id_user} deletado"})
        return jsonify({"message": "Usuário logado não pode ser deletado"}), 403

#Rota de teste
@app.route('/hello', methods=['GET'])
def hello_world():
    return "Hello Wordl"

if __name__ == '__main__':
    app.run(debug=True)