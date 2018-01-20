from flask import Flask, jsonify, request, render_template, flash, redirect, url_for, session as login_session, make_response, g, abort
from models import Base, User, Category, Item
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json, random, string
import httplib2
import requests
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///item-catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

# Web Pages

# Create anti-forgery state token
@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, CLIENT_ID=CLIENT_ID)

# Connect to Gmail
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
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

     # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if User is already connected.
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
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

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions

def createUser(login_session):
    new_user = User(username=login_session['username'], user_email=login_session['email'], user_picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(user_email=login_session['email']).one()
    return user.user_id


def getUserInfo(user_id):
    user = session.query(User).filter_by(user_id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(user_email=email).one()
        return user.user_id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
    	del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        del login_session['state']
        del login_session['user_id']
        #response = make_response(json.dumps('Successfully disconnected.'), 200)
        #response.headers['Content-Type'] = 'application/json'
        #return response
        flash("User successfully disconnected.")
        return redirect(url_for('home'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/')
def home():
	return render_template('home.html')

@app.route('/categories')
def categories():
	categories = session.query(Category).all()
	return render_template('categories.html', categories = categories)

@app.route('/items')
def items():
	items = session.query(Item).all()
	return render_template('items.html', items = items)

@app.route('/categories/<int:category_id>/items')
def category_items(category_id):
	items = session.query(Item).filter_by(category_id = category_id).all()
	return render_template('category_items.html', items = items)

@app.route('/categories/<int:category_id>/items/<int:item_id>')
def item(category_id, item_id):
	item = session.query(Item).filter_by(category_id = category_id).filter_by(item_id = item_id).first()
	return render_template('item_details.html', item = item)

@app.route('/categories/add', methods = ['GET', 'POST'])
def add_category():
	if 'email' not in login_session:
		flash("You need to log in.")
		return redirect(url_for('login'))
	if request.method == 'POST':
		category_name = request.form['category_name']
		if category_name is None or category_name == '':
			flash("Category Name cannot be empty.")
			return redirect(url_for('add_category'))
		if session.query(Category).filter_by(category_name = category_name).first() is not None:
			flash("Category already exists.")
			return redirect(url_for('add_category'))
		new_category = Category(category_name = category_name, user_id = login_session['user_id'])
		session.add(new_category)
		session.commit()
		flash("Category %s has been added." % category_name)
		return redirect(url_for('categories'))
	else:
		return render_template('add_category.html')

@app.route('/categories/<int:category_id>/edit', methods = ['GET', 'POST'])
def edit_category(category_id):
	if 'email' not in login_session:
		flash("You need to log in.")
		return redirect(url_for('login'))
	category = session.query(Category).filter_by(category_id = category_id).first()
	if category.user_id != login_session['user_id']:
		flash("You cannot edit this.")
		return redirect(url_for('home'))
	old_category_name = category.category_name
	if request.method == 'POST':
		category_name = request.form['category_name']
		if category_name is None or category_name == '':
			flash("Category Name cannot be empty.")
			return redirect(url_for('edit_category', category_id = category.category_id))
		category.category_name = category_name
		session.commit()
		flash("Category %s has been updated." % old_category_name)
		return redirect(url_for('categories'))
	else:
		return render_template('edit_category.html', category = category)

@app.route('/categories/<int:category_id>/delete', methods = ['GET', 'POST'])
def delete_category(category_id):
	if 'email' not in login_session:
		flash("You need to log in.")
		return redirect(url_for('login'))
	category = session.query(Category).filter_by(category_id = category_id).first()
	if category.user_id != login_session['user_id']:
		flash("You cannot delete this.")
		return redirect(url_for('home'))
	if request.method == 'POST':
		session.delete(category)
		session.commit()
		flash("Category %s has been deleted." % category.category_name)
		return redirect(url_for('categories'))
	else:
		return render_template('delete_category.html', category = category)

@app.route('/items/add', methods = ['GET', 'POST'])
def add_item():
	if 'email' not in login_session:
		flash("You need to log in.")
		return redirect(url_for('login'))
	if request.method == 'POST':
		item_name = request.form['item_name']
		item_description = request.form['item_description']
		category_id = request.form['category_id']
		if item_name is None or item_name == '' or category_id is None or category_id == '':
			flash("Empty item name or category name or both.")
			return redirect(url_for('add_item'))
		if session.query(Item).filter_by(item_name = item_name).filter_by(category_id = category_id).first() is not None:
			flash("Item already exists in the Category.")
			return redirect(url_for('add_item'))
		new_item = Item(item_name = item_name, item_description = item_description, category_id = category_id, user_id = login_session['user_id'])
		session.add(new_item)
		session.commit()
		flash("Item %s has been added." % item_name)
		return redirect(url_for('items'))
	else:
		categories = session.query(Category).all()
		if categories == []:
			flash("No Categories present. Please add a category first.")
			return redirect(url_for('items'))
		else:
			return render_template('add_item.html', categories = categories)

@app.route('/categories/<int:category_id>/items/<int:item_id>/edit', methods = ['GET', 'POST'])
def edit_item(category_id, item_id):
	if 'email' not in login_session:
		flash("You need to log in.")
		return redirect(url_for('login'))
	item = session.query(Item).filter_by(category_id = category_id).filter_by(item_id = item_id).first()
	if item.user_id != login_session['user_id']:
		flash("You cannot edit this.")
		return redirect(url_for('home'))
	old_item_name = item.item_name
	if request.method == 'POST':
		item_name = request.form['item_name']
		item_description = request.form['item_description']
		category_id = request.form['category_id']
		if item_name is not None and item_name != '':
			item.item_name = item_name
		if item_description is not None and item_description != '':
			item.item_description = item_description
		if category_id is not None and category_id != '':
			item.category_id = category_id
		session.commit()
		flash("Item %s has been updated." % old_item_name)
		return redirect(url_for('items'))
	else:
		categories = session.query(Category).all()
		return render_template('edit_item.html', item = item, categories = categories)

@app.route('/categories/<int:category_id>/items/<int:item_id>/delete', methods = ['GET', 'POST'])
def delete_item(category_id, item_id):
	if 'email' not in login_session:
		flash("You need to log in.")
		return redirect(url_for('login'))
	item = session.query(Item).filter_by(category_id = category_id).filter_by(item_id = item_id).first()
	if item.user_id != login_session['user_id']:
		flash("You cannot delete this.")
		return redirect(url_for('home'))
	item_name = item.item_name
	category_name = item.category.category_name
	if request.method == 'POST':
		session.delete(item)
		session.commit()
		flash("Item %s has been delted from category %s." % (item_name, category_name))
		return redirect(url_for('items'))
	else:
		return render_template('delete_item.html', item = item)

#API Authentication
@auth.verify_password
def verify_password(token, password):
    user_id = User.verify_auth_token(token)
    if user_id:
        user = session.query(User).filter_by(user_id = user_id).one()
    else:
        return False
    g.user = user
    return True

@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html', CLIENT_ID=CLIENT_ID)

@app.route('/oauth/<provider>', methods = ['POST'])
def api_login(provider):
    #STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print "Step 1 - Complete, received auth code %s" % auth_code
    if provider == 'google':
        #STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
          
        # Check that the access token is valid.
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            
        # # Verify that the access token is used for the intended user.
        # gplus_id = credentials.id_token['sub']
        # if result['user_id'] != gplus_id:
        #     response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # # Verify that the access token is valid for this app.
        # if result['issued_to'] != CLIENT_ID:
        #     response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response

        # stored_credentials = login_session.get('credentials')
        # stored_gplus_id = login_session.get('gplus_id')
        # if stored_credentials is not None and gplus_id == stored_gplus_id:
        #     response = make_response(json.dumps('Current user is already connected.'), 200)
        #     response.headers['Content-Type'] = 'application/json'
        #     return response
        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one
        
        #Get user info
        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)
      
        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']
        
        
     
        #see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(user_email=email).first()
        if not user:
            user = User(username = name, user_picture = picture, user_email = email)
            session.add(user)
            session.commit()

        

        #STEP 4 - Make token
        token = user.generate_auth_token(600)

        

        #STEP 5 - Send back token to the client 
        return jsonify({'token': token.decode('ascii')})
        
        #return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'

#API Endpoints
@app.route('/categories/api/json', methods = ['GET', 'POST'])
@auth.login_required
def categories_json():
	if request.method == 'GET':
		categories = session.query(Category).all()
		return jsonify(categories = [c.serialize for c in categories])
	if request.method == 'POST':
		category_name = request.args.get('category_name', '')
		if category_name is None or category_name == '':
			return jsonify({'error' : 'Empty category name.'})
		if session.query(Category).filter_by(category_name = category_name).first() is not None:
			return jsonify({'error' : 'Category already exists.'})
		new_category = Category(category_name = category_name)
		session.add(new_category)
		session.commit()
		return jsonify({'category' : new_category.serialize})


@app.route('/categories/<int:category_id>/api/json', methods = ['GET', 'PUT', 'DELETE'])
@auth.login_required
def category_json(category_id):
	category = session.query(Category).filter_by(category_id = category_id).first()
	if category is None:
		return jsonify({'error' : 'No Category with id %s.' % category_id})
	if request.method == 'GET':
		return jsonify({'category' : category.serialize})
	if request.method == 'PUT':
		category_name = request.args.get('category_name', '')
		if category_name is None or category_name == '':
			return jsonify({'error' : 'Empty category name. Update unsuccessful.'})
		category.category_name = category_name
		session.commit()
		return jsonify({'category' : category.serialize})
	if request.method == 'DELETE':
		session.delete(category)
		session.commit()
		return jsonify({'message' : 'Category %s has been deleted' % category.category_name})

@app.route('/items/api/json', methods = ['GET', 'POST'])
@auth.login_required
def items_json():
	if request.method == 'GET':
		items = session.query(Item).all()
		return jsonify(items = [i.serialize for i in items])
	if request.method == 'POST':
		item_name = request.args.get('item_name', '')
		item_description = request.args.get('item_description', '')
		category_id = request.args.get('category_id', '')
		if item_name is None or item_name == '' or category_id is None or category_id == '':
			return jsonify({'error' : 'Empty item name or category name or both.'})
		if session.query(Item).filter_by(item_name = item_name).filter_by(category_id = category_id).first() is not None:
			return jsonify({'error' : 'Item already exists in the Category.'})
		new_item = Item(item_name = item_name, category_id = category_id, item_description = item_description)
		session.add(new_item)
		session.commit()
		return jsonify({'item' : new_item.serialize})

@app.route('/categories/<int:category_id>/items/<int:item_id>/api/json', methods = ['GET', 'PUT', 'DELETE'])
@auth.login_required
def item_json(category_id, item_id):
	item = session.query(Item).filter_by(category_id = category_id).filter_by(item_id = item_id).first()
	if item is None:
		return jsonify({'error' : 'No Item with id %s and Category id %s.' % (item_id, category_id)})
	if request.method == 'GET':
		return jsonify({'item' : item.serialize})
	if request.method == 'PUT':
		item_name = request.args.get('item_name', '')
		item_description = request.args.get('item_description', '')
		category_id = request.args.get('category_id', '')
		if item_name is not None and item_name != '':
			item.item_name = item_name
		if item_description is not None and item_description != '':
			item.item_description = item_description
		if category_id is not None and category_id != '':
			item.category_id = category_id
		session.commit()
		return jsonify({'item' : item.serialize})
	if request.method == 'DELETE':
		session.delete(item)
		session.commit()
		return jsonify({'message' : 'Item %s in Category %s has been deleted' % (item.item_name, item.category_id)})

@app.route('/categories/<int:category_id>/items/api/json')
@auth.login_required
def category_items_json(category_id):
	items = session.query(Item).filter_by(category_id = category_id).all()
	return jsonify(items = [i.serialize for i in items])

if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)