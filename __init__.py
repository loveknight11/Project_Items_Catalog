
from flask import Flask, render_template, request, url_for, redirect
from flask import make_response, g, jsonify
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload
from models import Base, Categories, Items, Users
import random
import string
import os
import json
import httplib2
import requests
from werkzeug.utils import secure_filename
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

auth = HTTPBasicAuth()
app = Flask(__name__)
engine = create_engine('sqlite:////var/www/AlhussinyApp/AlhussinyApp/catalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
UPLOAD_FOLDER = "/var/www/AlhussinyApp/AlhussinyApp/static/"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

APPLICATION_NAME = "Catalog"
CLIENT_ID = json.loads(
    open('/var/www/AlhussinyApp/AlhussinyApp/client_secrets.json', 'r').read())['web']['client_id']


# verify username and password or token
@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = Users.verify_auth_token(username_or_token)
    # if user_id is None try to verify username and password
    if user_id:
        user = session.query(Users).filter_by(id=user_id).one()
    else:
        user = session.query(Users).filter_by(username=username_or_token).first()  # noqa: E501
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


# main route
@app.route('/')
@app.route('/catalog')
def showMain():
    categories = session.query(Categories).all()
    items = session.query(Items).order_by(Items.id.desc()).limit(5)
    return render_template('index.html', categories=categories, items=items)


# display all categories and add anew one
@app.route('/category', methods=['GET', 'POST'])
def addCategory():
    # to add a new category
    if login_session.get('username'):
        if request.method == "POST":
            category = Categories(name=request.form.get('name'))
            session.add(category)
            session.commit()
            return redirect(url_for('showMain'))
        else:
            return render_template('newCategory.html')
    else:
        return redirect(url_for('showLogin'))


# display category items
@app.route('/category/<category>')
def showCategory(category):
    items = session.query(Items).filter_by(category=category).all()
    categories = session.query(Categories).all()
    return render_template('categoryItems.html', items=items,
                           categories=categories, category=category,
                           itemsCount=len(items))


# add a new item
@app.route('/item/new', methods=['GET', 'POST'])
def addItem():
    if login_session.get('username'):
        if request.method == 'POST':
            category = session.query(Categories).filter_by(name=request.form.get("category")).one()  # noqa: E501
            # get item picture if selected
            pic = request.form.get("picture")
            if pic != "":
                if 'picture' in request.files:
                    file = request.files['picture']
                    if file.filename != '':
                        # save picture to upload folder and give it item name
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                  filename))
                        os.rename(os.path.join(app.config['UPLOAD_FOLDER'],
                                  filename),
                                  os.path.join(app.config['UPLOAD_FOLDER'],
                                  request.form.get("name")+".jpg"))
            item = Items(name=request.form.get("name"),
                         description=request.form.get("description"),
                         picture=request.form.get("name")+".jpg",
                         cat_id=category.id,
                         category=category.name,
                         user_id=login_session['username'])
            session.add(item)
            session.commit()
            return redirect(url_for("showMain"))
        else:
            categories = session.query(Categories).all()
            return render_template('newItem.html', categories=categories)
    else:
        return redirect(url_for('showLogin'))


# display item info
@app.route('/item/<int:item_id>')
def showItem(item_id):
    item = session.query(Items).filter_by(id=item_id).first()
    return render_template('item.html', item=item)


# delete item
@app.route('/item/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(item_id):
    if login_session.get('username'):
        item = session.query(Items).filter_by(id=item_id).first()
        if request.method == "POST":
            session.delete(item)
            session.commit()
            return redirect(url_for('showMain'))
        else:
            # check to see if user is logged in or direct to login page
            if login_session['username'] == item.user_id:
                return render_template('deleteItem.html', item=item)
            else:
                return "Not authorized to delete items you didn't create" 
    else:
        return redirect(url_for('showLogin'))


# edit item
@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(item_id):
    if login_session.get('username'):
        item = session.query(Items).filter_by(id=item_id).first()
        if request.method == 'POST':
            cat_name = request.form.get("category")
            category = session.query(Categories).filter_by(name=cat_name).one()
            pic = request.form.get("picture")
            # check to see if a new picture chosen and save it
            if pic != "":
                if 'picture' in request.files:
                    file = request.files['picture']
                    if file.filename != '':
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                                      item.name + ".jpg"))
                        except Exception:
                            pass

                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                  filename))
                        os.rename(os.path.join(app.config['UPLOAD_FOLDER'],
                                  filename),
                                  os.path.join(app.config['UPLOAD_FOLDER'],
                                  request.form.get("name")+".jpg"))
            item.name = request.form.get("name")
            item.description = request.form.get("description")
            item.category = category.name
            item.cat_id = category.id
            session.add(item)
            session.commit()
            return redirect(url_for('showCategory', category=item.category))
        else:
            if login_session['username'] == item.user_id:
                categories = session.query(Categories).all()
                return render_template('editItem.html', item=item,
                                       categories=categories)
            else:
                return "Not authorized to edit items you didn't create"
    else:
        return redirect(url_for('showLogin'))


# login route
@app.route('/clientOAuth', methods=['GET', 'POST'])
def showLogin():
    if request.method == 'GET':
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))  # noqa
        login_session['state'] = state
        return render_template('login.html', STATE=state)
    else:
        # verify username and password and add session
        username = request.form.get("username")
        password = request.form.get("password")
        if verify_password(username, password):
            login_session['provider'] = "local"
            login_session['username'] = g.user.username
            login_session['email'] = g.user.email
            login_session['picture'] = g.user.picture
            login_session['user_id'] = g.user.id
            return redirect(url_for('showMain'))
        else:
            return "Invalid Login Credentials"


# sign up route
@app.route('/signup')
def showSignup():
    return render_template('signup.html')


# add a new user route
@app.route('/newuser', methods=['POST'])
def newUser():
    login_session['provider'] = "local"
    login_session['username'] = request.form.get("username")
    login_session['password'] = request.form.get("password")
    login_session['email'] = request.form.get("email")
    pic = request.form.get("picture")
    if pic != "":
        if 'picture' in request.files:
            file = request.files['picture']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                os.rename(os.path.join(app.config['UPLOAD_FOLDER'],
                          filename), os.path.join(app.config['UPLOAD_FOLDER'],
                          request.form.get("username")+".jpg"))

    login_session['picture'] = os.path.join(app.config['UPLOAD_FOLDER'],
                                            request.form.get("username") +
                                            ".jpg")
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    return redirect(url_for('showMain'))


# connect using facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    token = result.split(',')[0].split(':')[1].replace('"', '')
    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    # add session values
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    output += '150px;-webkit-border-radius: 150px;-moz-border-radius:150px;">'
    return output


# connect using google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    userId = getUserId(data['email'])
    login_session['provider'] = "gmail"
    if userId is None:
        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']
        login_session['user_id'] = createUser(login_session)
    else:
        user = getUserInfo(userId)
        login_session['username'] = user.username
        login_session['picture'] = user.picture
        login_session['email'] = user.email
        login_session['user_id'] = user.id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    output += '150px;-webkit-border-radius: 150px;-moz-border-radius:150px;"> '
    return output


# disconnect route to check for provider and route to the right function
@app.route('/disconnect')
def disconnect():
    if login_session.get('provider') == 'facebook':
        return redirect('fbdisconnect')
    elif login_session.get('provider') == 'google':
        return redirect('gdisconnect')
    else:
        return redirect('localDisconnect')


# facebook disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)  # noqa
    h = httplib2.Http()
    h.request(url, 'DELETE')[1]
    # delete session values after logout
    del login_session['access_token']
    del login_session['facebook_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['provider']
    del login_session['user_id']
    return redirect(url_for('showMain'))


# google disconnect
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('showMain'))
    else:
        response = make_response(json.dumps('Failed to revoke token for user.',
                                            400))
        response.headers['Content-Type'] = 'application/json'
        return response


# disconnect local login
@app.route('/localDisconnect')
def localDisconnect():
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['provider']
    del login_session['user_id']
    return redirect(url_for('showMain'))


# json endpoint for categories
@app.route('/categories/json')
@auth.login_required
def allCatalogJson():
    categories = session.query(Categories).all()
    return jsonify(Categories=[i.serialize for i in categories])


# json end points for items
@app.route('/items/json')
@auth.login_required
def allItemsJson():
    items = session.query(Items).all()
    return jsonify(Items=[i.serialize for i in items])


# json endpoint for certain item
@app.route('/items/<int:item_id>/json')
@auth.login_required
def oneItemsJson(item_id):
    item = session.query(Items).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# json endpoint for the whole catalog
@app.route('/catalog/json')
@auth.login_required
def catalogJson():
    categories = session.query(Categories).options(joinedload(Categories.items)).all()  # noqa: E501
    return jsonify(Catalog=[dict(c.serialize,
                   items=[i.serialize for i in c.items]) for c in categories])


def getUserId(email):
    try:
        user = session.query(Users).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


def createUser(login_session):
    newUser = Users(username=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])
    if login_session.get('password'):
        newUser.hash_password(login_session['password'])

    session.add(newUser)
    session.commit()
    user = session.query(Users).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(Users).filter_by(id=user_id).one()
    return user


if __name__ == '__main__':
    app.secret_key = ''.join(random.choice(string.ascii_uppercase +
                             string.digits) for x in xrange(32))  # noqa
    app.debug = True
    app.run()

