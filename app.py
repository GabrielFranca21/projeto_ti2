from flask import Flask, render_template, request, redirect, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://queirozs01_add2:biel2015@mysql.queirozsantana.com.br/queirozsantana01'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
user = ""

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    
    cep = db.Column(db.String(9))
    rua = db.Column(db.String(100))
    bairro = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    estado = db.Column(db.String(100))
    complemento = db.Column(db.String(15))
    
# Rotas para as páginas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Lógica para registrar o usuário
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            new_user = User(name=name, email=email, password=hashed_password,cep=cep,rua=rua,bairro=bairro,cidade=cidade,estado=estado,complemento=complemento)
            
            hashed_password = generate_password_hash(password, method='sha256')
            return render_template('register.html', error='As senhas não coincidem.')
        
        cep = request.form['cep']
        rua = request.form['rua']
        complemento = request.form['complemento']
        estado = request.form['estado']
        cidade = request.form['cidade']
        bairro = request.form['bairro']
            
            
        
        
        new_user = User(name=name, email=email, password=hashed_password,cep=cep,rua=rua,bairro=bairro,cidade=cidade,estado=estado,complemento=complemento)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('/login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Lógica para autenticar o usuário
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Credenciais inválidas.')
            return render_template('login.html', error='Credenciais inválidas.')

        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/create_project', methods=['GET', 'POST'])
def create_project():
    if request.method == 'POST':
        # Lógica para criar um novo projeto
        return redirect(url_for('dashboard'))
    return render_template('create_project.html')

@app.route('/dashboard')
def dashboard():
    # Lógica para exibir o painel de controle
    return render_template('dashboard.html', user=user)


def recupera_cep(cep):
    request = requests.get('https://viacep.com.br/ws/{}/json/'.format(cep))
    address_data = request.json()
    
        
if __name__ == '__main__':
    app.run(debug=True)
