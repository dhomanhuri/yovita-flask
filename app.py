import base64
from flask import Flask, render_template, request, jsonify, send_file, url_for, redirect
from functools import wraps
from matplotlib.font_manager import json_dump, json_load
from sklearn.svm import SVR
import bcrypt
import jwt
import requests
import time
import matplotlib.pyplot as plt
import pandas as pd
import mysql.connector
import pickle
from flask_mail import Mail, Message
from flask_cors import CORS, cross_origin

from os.path import join, dirname, realpath
from utilsfile.token import generate_confirmation_token, confirm_token
# from utilsfile import generate_confirmation_token, confirm_token
from sklearn.preprocessing import MinMaxScaler

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config.from_pyfile('config.py')
mail = Mail(app)

SECRET_KEY = app.config['SECRET_KEY']

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = None
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split('Bearer ')[1]
            timestamp = jwt.decode(token, SECRET_KEY, algorithms='HS256')['age']
            if not token:
                return jsonify({'message': 'Invalid token.'}), 401
            if timestamp - round(time.time()) > 0 :
                return f(*args, **kwargs)
            else :
                return jsonify({'message': 'Expired token.'}), 401
        except jwt.exceptions.DecodeError as err:
            if 'Invalid token type' in str(err):
                return jsonify({'message': 'Invalid token type!' }), 401
            else:
                return jsonify({'message': 'Something went wrong' }), 500
    return decorated

def get_db_connection():
    return mysql.connector.connect(host=app.config['DB_HOST'],
                            database=app.config['DB_DATABASE'],
                            user=app.config['DB_USERNAME'],
                            password=app.config['DB_PASSWORD'])

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

def get_user():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f'''
        SELECT nama, email, level FROM users order by level desc;
    ''')
    users = cur.fetchall()
    cur.close()
    conn.close()

    result = [{'name' : user[0], 'email' : user[1], 'level' : user[2]} for user in users]
    return jsonify(result)

def get_readiness():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f'''
        SELECT id_kesiapan, tahun, bulan, tai, maintenance, readiness FROM readiness order by tahun asc, bulan asc;
    ''')
    data = cur.fetchall()
    cur.close()
    conn.close()

    result = [{'id' : datum[0], 'tahun' : datum[1], 'bulan' : datum[2], 'tai' : datum[3], 'maintenance' : datum[4], 'readiness' : datum[5]} for datum in data]
    return jsonify(result)

def get_readiness_by_tahun(tahun):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f'''
        SELECT id_kesiapan, tahun, bulan, tai, maintenance, readiness FROM readiness where tahun = '{tahun}' order by tahun asc, bulan asc;
    ''')
    data = cur.fetchall()
    cur.close()
    conn.close()

    result = [{'tahun' : datum[1], 'bulan' : datum[2], 'tai' : datum[3], 'maintenance' : datum[4], 'readiness' : datum[5]} for datum in data]
    file_path = join(app.config['UPLOAD_FOLDER'], 'data_'+tahun+'.csv')
    json_dump(result, file_path)
    return result

def insert_user(data):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        name = data['name']
        email = data['email']
        level = data['level']
        passwd = data['password'].encode('utf-8')
        salt = bcrypt.gensalt(rounds=16)
        hashed = bcrypt.hashpw(passwd, salt).decode('utf-8')
        cur.execute('INSERT INTO users(nama, email, password, level, konfirmasi)'
                    'VALUES (%s, %s, %s, %s, %s)',
                    (name, email, hashed, level, False))
        conn.commit()
        cur.close()
        conn.close()
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('user.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(email, subject, html)
        return jsonify({'message': 'success' }), 200
    except mysql.connector.Error as err:
        if 'Duplicate' in err.msg:
            return jsonify({'message': email + ' already exist!' }), 401
        else:
            return jsonify({'message': 'Something went wrong' }), 500

def update_user(data):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        email=data['email']
        name = data['name']
        passwd = data['password'].encode('utf-8')
        salt = bcrypt.gensalt(rounds=16)
        hashed = bcrypt.hashpw(passwd, salt).decode('utf-8')
        cur.execute('UPDATE users SET nama=%s, password=%s WHERE email=%s',
                    (name, hashed,email))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'success' }), 200
    except mysql.connector.Error as err:
        if 'Duplicate' in err.msg:
            return jsonify({'message': ' already exist!' }), 401
        else:
            return jsonify({'message': 'Something went wrong' }), 500

def delete_user(data):
    try:
        conn = get_db_connection()
        hapus=data['id']
        cur = conn.cursor()
        queryy='DELETE FROM users WHERE id_user=%s',hapus
        cur.execute(queryy)
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'success' }), 200
    except mysql.connector.Error as err:
        if 'Duplicate' in err.msg:
            return jsonify({'message': ' already exist!' }), 401
        else:
            return jsonify({'message': 'Something went wron'+queryy }), 500

def hapus_user(id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE id_user=%s',
                    (str(id)))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'message': 'success' }), 200
    except mysql.connector.Error as err:
        if 'Duplicate' in err.msg:
            return jsonify({'message': ' already exist!' }), 401
        else:
            return jsonify({'message': 'Something went wron'+str(id) }), 500

def _login(data):
    try: 
        conn = get_db_connection()
        cur = conn.cursor()
        email = data['email']
        passwd = data['password'].encode('utf-8')
        cur.execute(f'''
            SELECT * FROM users WHERE email = '{email}';
        ''')
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user == None: return jsonify({'message': 'Email or password does not match' }), 401
        if user[5] == 0: return jsonify({'message': 'Please confirm your email!' }), 401
        isValid = bcrypt.checkpw(passwd, user[3].encode('utf-8'))
        if isValid:
            return jsonify({'token': jwt.encode({'email': email, 'age': (round(time.time() + 86400)) }, SECRET_KEY),'role':user[4]})
        return jsonify({'message': 'Email or password does not match' }), 401
    except:
        return jsonify({'message': 'Something went wrong' }), 500

def parseCSV(filePath):
    conn = get_db_connection()
    cur = conn.cursor()
    col_names = ['tahun','bulan','tai','maintenance','readiness']
    csvData = pd.read_csv(filePath,names=col_names, header=0)
    for idx,row in csvData.iterrows():
        sql = "INSERT INTO readiness (tahun, bulan, tai, maintenance, readiness) VALUES (%s, %s, %s, %s, %s) as new on duplicate key update tahun = new.tahun, bulan = new.bulan, tai = new.tai, maintenance = new.maintenance, readiness = new.readiness"
        value = (row['tahun'],row['bulan'],row['tai'],row['maintenance'],row['readiness'])
        cur.execute(sql, value)
        conn.commit()

def function_svr(tahun):
    file_path = join(app.config['UPLOAD_FOLDER'], 'svr-2016-R2-Bagus')
    with open(file_path, 'rb') as r:
        svr = pickle.load(r)
    scaler = MinMaxScaler(feature_range = (1,20))
    raw_data = get_readiness_by_tahun(tahun)
    file_path = join(app.config['UPLOAD_FOLDER'], 'data_'+tahun+'.csv')
    df = pd.read_json(file_path)
    df['tai (scaled)']=scaler.fit_transform(df[['tai']])
    df['readiness (scaled)']=scaler.fit_transform(df[['readiness']])
    X = df.drop(['readiness', 'readiness (scaled)', 'tai', 'bulan', 'tahun'], axis=1).values
    y = df['readiness (scaled)'].values.reshape(-1,1)
    lsvr=svr.predict(X)
    x_ax = range(len(y))
    plt.plot(x_ax, scaler.inverse_transform(y.reshape(-1,1)), label="actual")
    plt.plot(x_ax, scaler.inverse_transform(lsvr.reshape(-1,1)), label="predicted")
    plt.title("Readiness and predicted data")
    plt.ylabel('Readiness')
    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    plt.legend(by_label.values(), by_label.keys())
    file_path = join(app.config['UPLOAD_FOLDER'], 'figure_'+tahun+'.png')
    plt.savefig(file_path)
    predicts=scaler.inverse_transform(lsvr.reshape(-1,1)).ravel()
    for idx, predict in enumerate(predicts):
        raw_data[idx]['predict'] = round(predict)
    with open(file_path, "rb") as image_file:
        return jsonify({'result': raw_data, 'image': base64.b64encode(image_file.read()).decode('utf-8')})

@app.route('/')
@cross_origin()
def index():
    requests.get('https://webhook.site/99ab9999-c5d6-4e66-a734-5d0dd96b96e3')
    return '/'

@app.route('/login', methods =['POST'])
@cross_origin()
def login():
    if request.method == 'POST':
        resp = _login(request.get_json())
        return resp

@app.route('/register', methods =['POST'])
@cross_origin()
def register():
    if request.method == 'POST':
        resp = insert_user(request.get_json())
        return resp

@app.route('/update', methods =['PUT'])
@cross_origin()
def update():
    if request.method == 'PUT':
        resp = update_user(request.get_json())
        return resp

@app.route('/delete', methods =['POST'])
@cross_origin()
def delete():
    if request.method == 'POST':
        resp = delete_user(request.get_json())
        return resp

@app.route('/hapus/<id>', methods =['DELETE'])
@cross_origin()
def hapus(id):
    if request.method == 'DELETE':
        resp = hapus_user(id)
        return resp

@app.route('/confirm/<token>')
@cross_origin()
def confirm_email(token):
    try:
        email = confirm_token(token)
        if email == False: return jsonify({'message': 'Invalid token!' }), 401
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(f'''
            UPDATE users SET users.konfirmasi = TRUE WHERE email = '{email}';
        ''')
        conn.commit()
        cur.close()
        conn.close()
        return redirect('https://yovita-reactjs.vercel.app', code=200)
    except:
        return jsonify({'message': 'Something went wrong' }), 500

@app.route('/predict/<tahun>', methods =['GET'])
@cross_origin()
@token_required
def svr(tahun):
    if request.method == 'GET':
        return function_svr(tahun)

@app.route('/upload', methods =['POST'])
@cross_origin()
@token_required
def upload():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            file_path = join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(file_path)
            parseCSV(file_path)
        return jsonify({'message': "success" }), 200

@app.route('/users', methods =['GET'])
@cross_origin()
@token_required
def get_users():
    if request.method == 'GET':
        return get_user()

@app.route('/readiness', methods =['GET'])
@cross_origin()
@token_required
def readiness():
    if request.method == 'GET':
        return get_readiness()

@app.route('/readiness/<id>', methods =['PATCH', 'DELETE'])
@cross_origin()
@token_required
def update_readiness(id):
    try:
        if request.method == 'PATCH':
            data = request.get_json()
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(f'''
                UPDATE readiness SET tahun = '{data['tahun']}', bulan = '{data['bulan']}',
                tai = {data['tai']}, maintenance = {data['maintenance']},
                readiness = {data['readiness']} WHERE id_kesiapan = '{id}';
            ''')
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({'message': 'ok' }), 200
        elif request.method == 'DELETE':
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(f'''
                DELETE FROM readiness where id_kesiapan = '{id}';
            ''')
            conn.commit()
            cur.close()
            conn.close()
            return jsonify({'message': 'ok' }), 200
    except:
        return jsonify({'message': 'Something went wrong' }), 500

@app.route('/webhook', methods =['GET'])
@cross_origin()
def webhook():
    if request.method == 'GET':
        requests.get('https://webhook.site/99ab9999-c5d6-4e66-a734-5d0dd96b96e3')
        return 'ok'

if __name__ == '__main__':
    app.debug = True
    app.run()