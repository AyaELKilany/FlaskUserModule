from flask import Flask , render_template , request , jsonify , redirect
import os
from flask_sqlalchemy import SQLAlchemy    
from werkzeug.security import generate_password_hash , check_password_hash
from oauthlib.oauth2 import WebApplicationClient
from flask_login import login_user ,UserMixin , LoginManager , login_required , current_user
import requests
import json

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", '55560994185-ftpsgpcb12cvm9tdev4gbn8j841108la.apps.googleusercontent.com')
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", 'rLHDTRK39ppDQNSV9IREkgPc')
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__) 
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.secret_key = "v3ry_s3cr3t_k3y"

login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

client = WebApplicationClient(GOOGLE_CLIENT_ID)

db = SQLAlchemy(app)
class Users(db.Model , UserMixin):
    id = db.Column(db.String(1000) , primary_key=True)
    firstname = db.Column(db.String(200) , nullable=False)
    lastname = db.Column(db.String(200) , nullable=False)
    username = db.Column(db.String(200) , unique=True , nullable=False)
    role = db.Column(db.String(10) , nullable=False)
    phonenumber = db.Column(db.String(11) , nullable=False) 
    email = db.Column(db.String(200) , unique=True , nullable=False)
    password = db.Column(db.String(200) , nullable=False)

    def to_json(self):
        json_user = {
            'user_id': self.id,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'phonenumber': self.phonenumber,
            'username': self.username,
            'email': self.email,
            'role': self.role
        }

        return json_user

    def __repr__(self):
        return f"id = {self.id}, username = {self.username} , firstname = {self.firstname} , lastname = {self.lastname} , role = {self.role} , phonenumber = {self.phonenumber} , email = {self.email} , password = {self.password}"
    

@app.route('/' , methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = Users.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return "Please check your login details and try again."
    else:

        login_user(user)
        return "Logged in"


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json() 

@app.route('/login')
def login_OAuth2():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email" , "profile"],
    )
    print(request_uri )
    return redirect(request_uri)



@app.route("/login/callback")
def callback():
    code = request.args.get("code")
    print(code)

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    ) 

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    if not Users.query.filter_by(id = unique_id).first():
        user =Users(id=(unique_id), firstname='ss' , lastname='sss' , username=users_name, role='Admin',  phonenumber='4637289039487' , email=users_email,   password = '12345678')
        db.session.add(user)
        db.session.commit()

    user = Users(
        id=unique_id, username=users_name, email=users_email
    )
    login_user(user)

    return redirect('http://127.0.0.1:5000/Users',code=303)


@app.route('/signup', methods=['POST'])
def signup():
    firstname = request.json.get('firstname')
    lastname = request.json.get('lastname')
    Username = request.json.get('username')
    role = request.json.get('user_role')
    phonenumber = request.json.get('phonenumber')
    email = request.json.get('email')
    password = request.json.get('password')

    user = Users.query.filter_by(email=email).first()
    if user:
        return 'Email address already exists.'

    if role in ['Client' , 'Chef' , 'Waiter' , 'Admin']:
        New_User = Users(firstname=firstname , lastname=lastname , username=Username, phonenumber=phonenumber , email=email , role=role , password= generate_password_hash(password, method='sha256'))
        try:
            db.session.add(New_User)    
            db.session.commit()
            return 'Done'

        except Exception as inst:
            d = inst
            return jsonify(str(d.args[0]))
    else:
        return 'Provided role is not valid'


@app.route('/Users' , methods=['GET'])
@login_required
def All_Users():
    
    if current_user.role == 'Admin':
        all_Users = Users.query.all()
        json_Users = []
        for user in all_Users:
            user = user.to_json()
            json_Users.append(user)
        return  jsonify(json_Users)  
    else:
        return 'Unauthorized'      

if __name__ =="__main__":
    app.run(debug=False)