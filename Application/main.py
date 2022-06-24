import re
from traceback import print_tb
from flask_security import Security
from flask_apscheduler import APScheduler
from flask import send_file, session as ses
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from jinja2 import Environment
jinja_env = Environment(autoescape=True)
import json,uuid,os
from flask import jsonify
import io,csv
from applications.validation import No_cards_error,Invalid_error
from datetime import datetime ,timedelta 
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager,login_required ,logout_user, current_user 
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
from flask_cors import CORS, cross_origin

basedir = os.path.abspath(os.path.dirname(__file__))

regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flashcard.sqlite3'
app.config['SECRET_KEY'] = 'secretkey'
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
security = Security(app)
scheduler = APScheduler()

app.config.from_object(__name__)
cors = CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
@login_manager.user_loader
def user_loader(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        return user
    return None


class deck_info(db.Model):
    Deck_id = db.Column(db.String, primary_key = True, nullable = False)
    Deck_name = db.Column(db.String, nullable = False)
    Deck_location = db.Column(db.String, nullable = False)
    db.UniqueConstraint(Deck_id,Deck_name)

class User(db.Model ,UserMixin):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True, nullable = False)
    Username = db.Column(db.String, nullable = False)
    Password = db.Column(db.String,nullable = False)
    db.UniqueConstraint(id,Username)
    authenticated = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.String)

    def is_authenticated(self):
     return self._authenticated
    

class Dashboard_info(db.Model):
    id = db.Column(db.Integer, primary_key = True, autoincrement = True,nullable = False)
    User_id = db.Column(db.Integer, db.ForeignKey(User.id),nullable = False)
    Deck_id = db.Column(db.String, db.ForeignKey('deck_info.Deck_id'), nullable = False)
    Score = db.Column(db.Integer)
    LastReviewTime = db.Column(db.String)

@app.route('/dashboard', methods = ['GET','POST'])
# @login_required
def dashboard():
    if(request.method == 'GET'):
        User_id = ses['user_id']
    else:
        get_data = request.get_json()
        User_id = get_data.get('user_id')
    dash = Dashboard_info.query.all()
    Decks = []
    creds = User.query.get(User_id)
    name = creds.Username
    for d in dash:
        decks = deck_info.query.get(d.Deck_id)
        deckDetails = {}
        deckDetails['id'] = d.Deck_id
        deckDetails['name'] = decks.Deck_name
        deckDetails['score'] = d.Score
        deckDetails['lastReviewTime'] = d.LastReviewTime
        Decks.append(deckDetails)
    if(request.method == 'GET'):
        return render_template('dashboard.html', dashboard = dash, User_id = User_id,Username = name, decks=Decks)
    else:
        return jsonify({"message":"success","data": { "User_id" : User_id, "Username" : name, "decks": Decks}})

@app.route('/login', methods = ['GET','POST'])
def login():
    if(request.method == 'GET'):
        return render_template('login.html')
    else:
        post_data = request.get_json()

        uname  = post_data.get('username')
        password = post_data.get('password')
        now = datetime.now()
        now = now.strftime("%d/%m/%Y %H:%M:%S")
        try :
         user = db.session.query(User).filter(User.Username == uname).first()
        except Exception as e:
          print(e)
        if user:
            if bcrypt.check_password_hash(user.Password,password):
                ses.permanent = True
                ses["User_id"] = user.id
                admin = User.query.filter_by(Username=uname).first()	
                admin.last_login = now
                User.last_login = now
                db.session.commit()
                if request.form.get('remember'):
                   login_user(user, remember= True)
                else :     
                   login_user(user)
                dash = Dashboard_info.query.filter(Dashboard_info.User_id == user.id)
                Decks=[]
                creds = User.query.get(user.id)
                name = creds.Username
                for d in dash:
                    decks = deck_info.query.get(d.Deck_id)
                    deckDetails = {}
                    deckDetails['id'] = d.Deck_id
                    deckDetails['name'] = decks.Deck_name
                    deckDetails['score'] = d.Score
                    deckDetails['lastReviewTime'] = d.LastReviewTime
                    Decks.append(deckDetails)
                return jsonify({"message":"success","User_id": user.id, "decks": Decks, "username": name})
            else:
                return redirect('/login/invalid')
        return render_template('invalid.html', argument = 'user')

@app.route('/logout')
def logout():
  logout_user()
  return redirect(url_for('login'))

@app.route('/login/invalid')
def InvalidLogin():
  return render_template('invalid.html', argument = 'login')

@app.route('/invalid/<string:argument>/')
def Invalid(argument):
    User_id = ses["User_id"]
    return render_template('invalid.html', argument = argument)

@app.route('/about.html')
def about():
    return render_template('about.html')

@app.route('/API_documentation.yaml')
def API():
    return render_template('API_documentation.yaml')


@app.route('/signup', methods = ['GET','POST'])
def signup():
    if(request.method == 'GET'):
        return render_template('signup.html')
    else:
        get_data = request.get_json()
        uname = get_data.get('username')
        if(re.fullmatch(regex, uname)):
           pass
        else:
           return render_template('Invalid_deck.html', data = "Email id")
        password = get_data.get('password')
        hashed_password = bcrypt.generate_password_hash(password)
        now = datetime.now()	
        now = now.strftime("%d/%m/%Y %H:%M:%S")	
        creds = User(Username = uname, Password = hashed_password ,last_login = now)
        db.session.add(creds)
        db.session.commit()
        return jsonify({"message":"success"})

@app.route('/update/<int:User_id>/<string:deck_id>',methods=['PUT'])
def Update(deck_id,User_id):
    if(request.method== 'PUT'):
        data=request.json
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error("USER ID", status_code=400)
        if data:
           
            try:
                deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
           
                location=deck_records.Deck_location
           
                deck_name=deck_records.Deck_name
           
            except exc.SQLAlchemyError:
                raise Invalid_error('Deck_id',status_code=400)
            data_json = io.open(location,'r',encoding='UTF-8').read()
            data_dic=json.loads(data_json)
            for keys in data:
                data_dic["cards"][keys]= data[keys]
            with open(location, "w") as outfile:
                json.dump(data_dic, outfile, indent = 4)
            dash = Dashboard_info.query.filter(Dashboard_info.User_id == User_id)
            Decks=[]
            creds = User.query.get(User_id)
            name = creds.Username
            for d in dash:
                decks = deck_info.query.get(d.Deck_id)
                deckDetails = {}
                deckDetails['id'] = d.Deck_id
                deckDetails['name'] = decks.Deck_name
                deckDetails['score'] = d.Score
                deckDetails['lastReviewTime'] = d.LastReviewTime
                Decks.append(deckDetails)
            return jsonify({"message":"success","deck":data_dic['cards'], "decks": Decks})
        else: 
            raise No_cards_error()


@app.route('/update', methods = ['GET','POST'])
def Update_deck():
    if(request.method == 'GET'):
        User_id = ses["User_id"]
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID/DECK ID")
        creds = User.query.get(User_id)
        name = creds.Username        
        return render_template('updatedeck1.html',Username = name)
    else:
        deckId = request.form['deckId']
        cardNo  = request.form['cardno']
        url = '/updatedeck/' + deckId + '/' + str(cardNo)
        return redirect(url)

@app.route('/updatedeck/<string:deckId>/<int:cardNo>', methods = ['GET','POST'])    
def Update_card(deckId,cardNo):
    if(request.method == 'GET'):
        User_id = ses["User_id"]
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deckId ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "USER ID/DECK ID")
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()
        except exc.SQLAlchemyError:
                return render_template('Invalid_deck.html', data = "DECK ID")
        deckName=deck_records.Deck_name
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('updatedeck2.html',cardNo=cardNo,deckName=deckName,Username = name)
    else:
        r = request.form
        r = str(r)
        r = r[20:-2]
        data = str2tupleList(r, cardNo)
        User_id = ses["User_id"]
        if data=={'':''}:
            return render_template('NoCards.html')
        deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one_or_none()
        if deck_records is not None:
            location=deck_records.Deck_location
            deckName=deck_records.Deck_name
            data_json = io.open(location,'r',encoding='UTF-8').read()
            data_dic=json.loads(data_json)
            for keys in data:
                data_dic["cards"][keys]= data[keys]
            with open(location, "w") as outfile:
                json.dump(data_dic, outfile, indent = 4)
            creds = User.query.get(User_id)
            name = creds.Username    
            return render_template('showDeck.html',Username=name,deckName=deckName,deckId=deckId,cards=data_dic['cards'],User_id=User_id)
        else :
            return render_template('Invalid_deck.html', data = "DECK ID")

@app.route('/delete/<int:User_id>/<string:deck_id>',methods=['DELETE'])
def Delete(deck_id,User_id):    
    if(request.method=='DELETE'):
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error('USER ID/DECK ID,this deck for this user', status_code=400)
        deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
        location=deck_records.Deck_location
        os.remove(location)
        deck=deck_info.query.filter(deck_info.Deck_id==deck_id).delete()
        db.session.commit()
        dash=Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id).delete()
        db.session.commit()
        dash = Dashboard_info.query.filter(Dashboard_info.User_id == User_id)
        Decks=[]
        creds = User.query.get(User_id)
        name = creds.Username
        for d in dash:
            decks = deck_info.query.get(d.Deck_id)
            deckDetails = {}
            deckDetails['id'] = d.Deck_id
            deckDetails['name'] = decks.Deck_name
            deckDetails['score'] = d.Score
            deckDetails['lastReviewTime'] = d.LastReviewTime
            Decks.append(deckDetails)
        return jsonify({"message":"Deck Removed", "decks": Decks})

@app.route('/delete',methods=['POST','GET'])
def Delete_deck():
    User_id = ses["User_id"]
    if(request.method=='GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('deleteDeck1.html',Username=name)
    else:
        deckId = request.form['deckId']   
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "DECK ID")
        location=deck_records.Deck_location
        os.remove(location)
        deck_info.query.filter(deck_info.Deck_id==deckId).delete()
        db.session.commit()
        Dashboard_info.query.filter(Dashboard_info.Deck_id==deckId).delete()
        db.session.commit()
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('deleteDeck2.html',User_id=User_id,Username=name)

@app.route('/remove/<int:User_id>/<string:deck_id>/<string:card_name>',methods=['PUT'])
def Remove_card_info(deck_id,card_name,User_id):
    if(request.method== 'PUT'):
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deck_id ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error("USER ID/DECK ID,this deck for this user", status_code=400)
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error('Deck_id')   
        location=deck_records.Deck_location
        deck_name=deck_records.Deck_name
        data_json = io.open(location,'r',encoding='UTF-8').read()
        data_dic=json.loads(data_json)
        try:
            del data_dic["cards"][card_name]
        except KeyError:
            raise Invalid_error('card_name',status_code=404)    
        with open(location, "w") as outfile:
            json.dump(data_dic, outfile, indent = 4)
        return jsonify({"message":"success","currentdeck":data_dic['cards']})


@app.route('/remove',methods=['GET','POST'])
def remove_card():
    User_id = ses["User_id"]
    if(request.method == 'GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('remove1.html',Username = name)
    elif(request.method =='POST'):
        deckId = request.form['deckId']
        url = '/remove/'+deckId
        return redirect(url)

@app.route('/remove/<string:deckId>',methods=['GET','POST'])
def remove_card2(deckId):
    User_id = ses["User_id"]
    if(request.method=='GET'):
        try:
            Dashboard_info.query.filter(Dashboard_info.Deck_id==deckId ,Dashboard_info.User_id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "USER ID/DECK ID")
        deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()   
        location=deck_records.Deck_location
        deckName=deck_records.Deck_name
        data_json = io.open(location,'r',encoding='UTF-8').read()
        data_dic=json.loads(data_json)
        data_dic=dict(data_dic)
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('remove2.html',cards=data_dic['cards'],Username =name)
    elif(request.method=='POST'):
        cardName = request.form['front']
        try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deckId).one()
        except exc.SQLAlchemyError:
            return render_template('Invalid_deck.html', data = "DECK ID")
        location=deck_records.Deck_location
        deckName=deck_records.Deck_name
        data_json = io.open(location,'r',encoding='UTF-8').read()
        data_dic=json.loads(data_json)
        try:  
            del data_dic["cards"][cardName]
        except KeyError:
            return render_template('No_such_card.html') 
        with open(location, "w") as outfile:
            json.dump(data_dic, outfile, indent = 4)
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('showDeck.html',deckName=deckName,Username=name,deckId=deckId,cards=data_dic['cards'],User_id=User_id)    


@app.route('/getuserid/<string:Username>/<string:password>',methods=['GET'])
def getuserid(Username, password):
        
        cred = User.query.filter(User.Username == Username).one_or_none()

        if(cred):
            if bcrypt.check_password_hash(cred.Password,password):
              p = cred.id
              dic  = {}
              dic['User_id'] = p
              
            return jsonify(dic)

        else:
            raise Invalid_error('Username/password', status_code = 400)
        
@app.route('/new/<int:User_id>/<string:deck_name>',methods=['POST'])
def New_deck(deck_name,User_id):
    if(request.method == 'POST'):
        data=request.get_json()
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            raise Invalid_error("USER ID",status_code=400)
        if data :
            deckId = str(uuid.uuid4())[:8]
            dic = {"Deck_name":deck_name, "Deck_id":deckId,"cards":data}
            MyJson = json.dumps(dic, indent = 4)
            deck_location = str(os.path.join(basedir, "json/"+deck_name+".json"))
            F =open(deck_location, 'w')
            with open( deck_location, "w") as outfile:
                outfile.write(MyJson)  
            cards = deck_info(Deck_id=deckId,Deck_name=deck_name,Deck_location=deck_location)
            db.session.add(cards)
            db.session.commit()
            dash = Dashboard_info(Deck_id = deckId, User_id = User_id, Score = 0, LastReviewTime = '0')
            db.session.add(dash)
            db.session.commit()
            dash = Dashboard_info.query.filter(Dashboard_info.User_id == User_id)
            Decks=[]
            creds = User.query.get(User_id)
            name = creds.Username
            for d in dash:
                decks = deck_info.query.get(d.Deck_id)
                deckDetails = {}
                deckDetails['id'] = d.Deck_id
                deckDetails['name'] = decks.Deck_name
                deckDetails['score'] = d.Score
                deckDetails['lastReviewTime'] = d.LastReviewTime
                Decks.append(deckDetails)
            return jsonify({"message": "success", "decks":Decks})
        else :
            raise No_cards_error(status_code=400)


@app.route('/new', methods = ['GET','POST'])
def new_deckfunc():
    User_id = ses["User_id"]
    if(request.method == 'GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username
        return render_template('createdeck1.html',Username = name)
    else:      
        deckName = request.form['deckname']
        cardNo  = request.form['cardno']
        url = '/setdeck/' + deckName + '/' + str(cardNo)
        return redirect(url)
              
@app.route('/setdeck/<string:deckName>/<int:cardNo>', methods = ['GET','POST'])
def create(deckName, cardNo):
    User_id = ses["User_id"]
    if(request.method == 'GET'):
        try:
            User.query.filter(User.id==User_id).one()
        except exc.SQLAlchemyError:
            return render_template("Invalid_deck.html",data= "USER ID")
        creds = User.query.get(User_id)
        name = creds.Username    
        return render_template('createdeck2.html',Username=name,cardno = cardNo, deckname = deckName)
    else:
        r = request.form
        r = str(r)
        r = r[20:-2]
        data = str2tupleList(r, cardNo)
        if data!= { '': ''}:
            deckId = str(uuid.uuid4())[:8]
            dic = {"Deck_name":deckName, "Deck_id":deckId,"cards":data}
            MyJson = json.dumps(dic, indent = 4)
            deckLocation = str(os.path.join(basedir, "json/"+deckName+".json"))
            F =open(deckLocation, 'w')
            with open( deckLocation, "w") as outfile:
                outfile.write(MyJson)  
            cards = deck_info(Deck_id=deckId,Deck_name=deckName,Deck_location=deckLocation)
            db.session.add(cards)
            db.session.commit()
            dash = Dashboard_info(Deck_id = deckId, User_id = User_id, Score = 0, LastReviewTime = '0')
            db.session.add(dash)
            db.session.commit()
            creds = User.query.get(User_id)
            name = creds.Username
            return render_template('showDeck.html',deckName=deckName,deckId=deckId,cards=dic["cards"],User_id=User_id,Username=name)
        else : 
            return render_template('NoCards.html')

def str2tupleList(s, cardNo):
    r = eval( "[%s]" % s )
    dic = {}
    for i in range(0,cardNo):
        dic[r[i][1]] = r[i+cardNo][1]
    return dic 

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/review', methods=['GET','POST'])
def card_detail():
    post_data = request.get_json()
    User_id = post_data['User_id']
    Deck_id = post_data['deckid']
    score = post_data['score']
    if score == 0:
        Deck_details = deck_info.query.filter(deck_info.Deck_id == Deck_id).one()
        Deck_Name = Deck_details.Deck_name
        SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
        Filename= Deck_Name +'.json'
        json_url = os.path.join(SITE_ROOT, "json/", Filename)
        data = json.load(open(json_url))
        decks = data['cards']
        return jsonify({"User_id": User_id, "deckid": Deck_id, "deckname": Deck_Name, "deck": decks})
    
    if(score != 0):
        dash= Dashboard_info.query.filter((Dashboard_info.User_id == User_id) & (Dashboard_info.Deck_id == Deck_id)).one()
        dash.Score += int(score)
        now = datetime.now()
        now = now.strftime("%d/%m/%Y %H:%M:%S")
        dash.LastReviewTime = now
        db.session.commit()
        dash = Dashboard_info.query.filter(Dashboard_info.User_id == User_id)
        Decks = []
        creds = User.query.get(User_id)
        name = creds.Username
        for d in dash:
            decks = deck_info.query.get(d.Deck_id)
            deckDetails = {}
            deckDetails['id'] = d.Deck_id
            deckDetails['name'] = decks.Deck_name
            deckDetails['score'] = d.Score
            deckDetails['lastReviewTime'] = d.LastReviewTime
            Decks.append(deckDetails)
        return jsonify({"User_id": User_id, "decks": Decks})
    

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)


scheduler = APScheduler()


@app.route("/email", methods=['POST'])
def email():	
    	
    from_addr='flashcard.web.mail@gmail.com'	
    user = User.query.all()	
    mail_ids = []	
    for use in user :	
        timer = datetime.now() - timedelta(days=1)	
        timer = timer.strftime("%d/%m/%Y %H:%M:%S")	
        past = use.last_login	
        if (timer > past) : 	
            mail_ids.append(use.Username)	
    try :            	
        to_addr=mail_ids	
        msg=MIMEMultipart()	
        msg['From']=from_addr	
        msg['To']=" ,".join(to_addr)	
        msg['subject']='Daily Reminder'	
        report_file = open('./templates/alert.html')	
        html =  report_file.read()	
        msg.attach(MIMEText(html,'html'))	
        email='flashcard.web.mail@gmail.com'	
        password='xjwyyuodhanjvnav'	
        mail=smtplib.SMTP('smtp.gmail.com',587)	
        mail.ehlo()	
        mail.starttls()	
        mail.login(email,password)	
        text=msg.as_string()	
        mail.sendmail(from_addr,to_addr,text)	
        mail.quit()	
        return jsonify("mail sent")	
    except :	
        return jsonify("ALl user logged in today")


@app.route("/email/report", methods=['POST'])
def email_report():
    from_addr='flashcard.web.mail@gmail.com'
    user = User.query.all()
    mail_ids = []
    for use in user :
        to_addr=[use.Username]
        msg=MIMEMultipart()
        msg['From']=from_addr
        msg['To']=" ,".join(to_addr) 
        msg['subject']='Daily Reminder'
        report_file = open('./templates/sample.html',"r")
        
        html =  report_file.read()
        template = jinja_env.from_string(html)
        obj = User.query.filter(User.Username==use.Username).one()
            
        decks = Dashboard_info.query.filter(Dashboard_info.User_id == int(obj.id)).all()
            
        deck_dicts = {}
        for d in decks:
            deck_obj = deck_info.query.filter(deck_info.Deck_id==d.Deck_id).one_or_none()
            try : 
                deck_dicts[deck_obj.Deck_name] = d.Score 
            except :
                continue
            html = template.render(decks=deck_dicts)
        
            msg.attach(MIMEText(html,'html'))
            email='flashcard.web.mail@gmail.com'
            password='xjwyyuodhanjvnav'
            mail=smtplib.SMTP('smtp.gmail.com',587)
            mail.ehlo()
            mail.starttls()
            mail.login(email,password)
            text=msg.as_string()
            mail.sendmail(from_addr,to_addr,text)
            mail.quit()
    return jsonify({"message":"success"})

@app.route('/upload',methods = ['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
      return render_template('upload.html')
    else:
      Userid = request.form['user_id']
      deckName = request.form['deckname']
      f = request.files['file']
      f.filename = deckName + ".csv"
      f.save(secure_filename(f.filename ))
      data = {}
      input_file = csv.DictReader(open(deckName+".csv"))
      for row in input_file:
        data[row["Front"]] = row["Back"]
      if data:
            deckId = str(uuid.uuid4())[:8]
            dic = {"Deck_name":deckName, "Deck_id":deckId,"cards":data}
            MyJson = json.dumps(dic, indent = 4)
            deck_location = str(os.path.join(basedir, "json/"+deckName+".json"))
            F =open(deck_location, 'w')
            with open( deck_location, "w") as outfile:
                outfile.write(MyJson)  
            cards = deck_info(Deck_id=deckId,Deck_name=deckName,Deck_location=deck_location)
            db.session.add(cards)
            db.session.commit()
            dash = Dashboard_info(Deck_id = deckId, User_id = Userid, Score = 0, LastReviewTime = '0')
            db.session.add(dash)
            db.session.commit()
            dash = Dashboard_info.query.filter(Dashboard_info.User_id == Userid)
            Decks = []
            creds = User.query.get(Userid)
            for d in dash:
                decks = deck_info.query.get(d.Deck_id)
                deckDetails = {}
                deckDetails['id'] = d.Deck_id
                deckDetails['name'] = decks.Deck_name
                deckDetails['score'] = d.Score
                deckDetails['lastReviewTime'] = d.LastReviewTime
                Decks.append(deckDetails)
            return jsonify({"message":"success","decks": Decks})

@app.route('/export/<string:deck_id>', methods=['GET'])
def export(deck_id):
    if request.method == 'GET':
     try:
            deck_records= deck_info.query.filter(deck_info.Deck_id==deck_id).one()
           
            location=deck_records.Deck_location
           
            deck_name=deck_records.Deck_name
           
     except exc.SQLAlchemyError:
            raise Invalid_error('Deck_id',status_code=400)
    data_json = io.open(location,'r',encoding='UTF-8').read()
    data=json.loads(data_json)
    deck_name = data["Deck_name"]
    deck_id = data["Deck_id"]
    f = open("./csv/"+deck_name+"_"+deck_id +".csv" , "w")
    csvwriter = csv.writer(f)
    fields = ["Front" ,"Back"]
    csvwriter.writerow(fields)
    rows=[]
    for x in data["cards"]:
        front = x
        back = data["cards"][x]
        row = [front,back ]
        rows.append(row)
    
    csvwriter.writerows(rows) 
    f.close()
    uploads = "./csv/"+deck_name+"_"+deck_id +".csv"
  
    return send_file(uploads, as_attachment=True)

if __name__ == "__main__":
    scheduler.add_job(id = 'Scheduled Task1', func=email_report, trigger="interval", seconds=2538000)
    scheduler.add_job(id = 'Scheduled Task2', func=email, trigger="interval", seconds=84600)
    scheduler.start()
    app.run(debug = True)