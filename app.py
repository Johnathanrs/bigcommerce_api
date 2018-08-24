from bigcommerce.api import BigcommerceApi
import dotenv, os, sys, flask, requests, time
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask import json, Response, jsonify, request, render_template

# do __name__.split('.')[0] if initialising from a file not at project root
app = flask.Flask(__name__)

# Look for a .env file
if os.path.exists('.env'):
    dotenv.load_dotenv('.env')

# Load configuration from environment, with defaults
app.config['DEBUG'] = True if os.getenv('DEBUG') == 'True' else False
app.config['LISTEN_HOST'] = os.getenv('LISTEN_HOST', '0.0.0.0')
app.config['LISTEN_PORT'] = int(os.getenv('LISTEN_PORT', '5000'))
app.config['APP_URL'] = os.getenv('APP_URL', 'http://localhost:5000')  # must be https to avoid browser issues
app.config['APP_CLIENT_ID'] = os.getenv('APP_CLIENT_ID')
app.config['APP_CLIENT_SECRET'] = os.getenv('APP_CLIENT_SECRET')
app.config['SESSION_SECRET'] = os.getenv('SESSION_SECRET', os.urandom(64))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///data/hello_world.sqlite')
app.config['SQLALCHEMY_ECHO'] = app.config['DEBUG']

# Setup secure cookie secret
app.secret_key = app.config['SESSION_SECRET']

# Setup db
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bc_id = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    storeusers = relationship("StoreUser", backref="user")

    def __init__(self, bc_id, email):
        self.bc_id = bc_id
        self.email = email

    def __repr__(self):
        return '<User id=%d bc_id=%d email=%s>' % (self.id, self.bc_id, self.email)

class StoreUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, store, user, admin=False):
        self.store_id = store.id
        self.user_id = user.id
        self.admin = admin

    def __repr__(self):
        return '<StoreUser id=%d email=%s user_id=%s store_id=%d  admin=%s>' \
               % (self.id, self.user.email, self.user_id,  self.store.store_id, self.admin)

class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    store_hash = db.Column(db.String(16), nullable=False, unique=True)
    access_token = db.Column(db.String(128), nullable=False)
    scope = db.Column(db.String(256), nullable=False)
    admin_storeuser_id = relationship("StoreUser",
                                      primaryjoin="and_(StoreUser.store_id==Store.id, StoreUser.admin==True)")
    storeusers = relationship("StoreUser", backref="store")

    def __init__(self, store_hash, access_token, scope):
        self.store_hash = store_hash
        self.access_token = access_token
        self.scope = scope

    def __repr__(self):
        return '<Store id=%d store_hash=%s access_token=%s scope=%s>' \
               % (self.id, self.store_hash, self.access_token, self.scope)

#
# Error handling and helpers
#
def error_info(e):
    content = ""
    try:  # it's probably a HttpException, if you're using the bigcommerce client
        content += str(e.headers) + "<br>" + str(e.content) + "<br>"
        req = e.response.request
        content += "<br>Request:<br>" + req.url + "<br>" + str(req.headers) + "<br>" + str(req.body)
    except AttributeError as e:  # not a HttpException
        content += "<br><br> (This page threw an exception: {})".format(str(e))
    return content

@app.errorhandler(500)
def internal_server_error(e):
    content = "Internal Server Error: " + str(e) + "<br>"
    content += error_info(e)
    return content, 500

@app.errorhandler(400)
def bad_request(e):
    content = "Bad Request: " + str(e) + "<br>"
    content += error_info(e)
    return content, 400

# Helper for template rendering
def render(template, context):
    return flask.render_template(template, **context)

def client_id():
    return app.config['APP_CLIENT_ID']

def client_secret():
    return app.config['APP_CLIENT_SECRET']

#
# OAuth pages
#

# The Auth Callback URL. See https://developer.bigcommerce.com/api/callback
@app.route('/bigcommerce/callback', methods=['GET', 'POST'])
def auth_callback():
    # Put together params for token request
    code = flask.request.args['code']
    context = flask.request.args['context']
    scope = flask.request.args['scope']
    store_hash = context.split('/')[1]
    redirect = app.config['APP_URL'] + flask.url_for('auth_callback')

    # Fetch a permanent oauth token. This will throw an exception on error,
    # which will get caught by our error handler above.
    client = BigcommerceApi(client_id=client_id(), store_hash=store_hash)
    token = client.oauth_fetch_token(client_secret(), code, context, scope, redirect)
    bc_user_id = token['user']['id']
    email = token['user']['email']
    access_token = token['access_token']

    # Create or update store
    store = Store.query.filter_by(store_hash=store_hash).first()
    if store is None:
        store = Store(store_hash, access_token, scope)
        db.session.add(store)
        db.session.commit()
    else:
        store.access_token = access_token
        store.scope = scope
        db.session.add(store)
        db.session.commit()
        # If the app was installed before, make sure the old admin user is no longer marked as the admin
        oldadminuser = StoreUser.query.filter_by(store_id=store.id, admin=True).first()
        if oldadminuser:
            oldadminuser.admin = False
            db.session.add(oldadminuser)

    # Create or update global BC user
    user = User.query.filter_by(bc_id=bc_user_id).first()
    if user is None:
        user = User(bc_user_id, email)
        db.session.add(user)
    elif user.email != email:
        user.email = email
        db.session.add(user)

    # Create or update store user
    storeuser = StoreUser.query.filter_by(user_id=user.id, store_id=store.id).first()
    if not storeuser:
        storeuser = StoreUser(store, user, admin=True)
    else:
        storeuser.admin = True
    db.session.add(storeuser)
    db.session.commit()

    # Log user in and redirect to app home
    flask.session['storeuserid'] = storeuser.id
    return flask.redirect(app.config['APP_URL'])

# The Load URL. See https://developer.bigcommerce.com/api/load
@app.route('/bigcommerce/load')
def load():
    # Decode and verify payload
    payload = flask.request.args['signed_payload']
    user_data = BigcommerceApi.oauth_verify_payload(payload, client_secret())
    if user_data is False:
        return "Payload verification failed!", 401

    bc_user_id = user_data['user']['id']
    email = user_data['user']['email']
    store_hash = user_data['store_hash']

    # Lookup store
    store = Store.query.filter_by(store_hash=store_hash).first()
    if store is None:
        return "Store not found!", 401

    # Lookup user and create if doesn't exist (this can happen if you enable multi-user
    # when registering your app)
    user = User.query.filter_by(bc_id=bc_user_id).first()
    if user is None:
        user = User(bc_user_id, email)
        db.session.add(user)
        db.session.commit()
    storeuser = StoreUser.query.filter_by(user_id=user.id, store_id=store.id).first()
    if storeuser is None:
        storeuser = StoreUser(store, user)
        db.session.add(storeuser)
        db.session.commit()

    # Log user in and redirect to app interface
    flask.session['storeuserid'] = storeuser.id
    return flask.redirect(app.config['APP_URL'])

# The Uninstall URL. See https://developer.bigcommerce.com/api/load
@app.route('/bigcommerce/uninstall')
def uninstall():
    # Decode and verify payload
    payload = flask.request.args['signed_payload']
    user_data = BigcommerceApi.oauth_verify_payload(payload, client_secret())
    if user_data is False:
        return "Payload verification failed!", 401

    # Lookup store
    store_hash = user_data['store_hash']
    store = Store.query.filter_by(store_hash=store_hash).first()
    if store is None:
        return "Store not found!", 401

    # Clean up: delete store associated users. This logic is up to you.
    # You may decide to keep these records around in case the user installs
    # your app again.
    storeusers = StoreUser.query.filter_by(store_id=store.id)
    for storeuser in storeusers:
        db.session.delete(storeuser)
    db.session.delete(store)
    db.session.commit()

    return flask.Response('Deleted', status=204)

# The Remove User Callback URL.
@app.route('/bigcommerce/remove-user')
def remove_user():
    # Decode and verify payload
    payload = flask.request.args['signed_payload']
    user_data = BigcommerceApi.oauth_verify_payload(payload, client_secret())
    if user_data is False:
        return "Payload verification failed!", 401

    # Lookup store
    store_hash = user_data['store_hash']
    store = Store.query.filter_by(store_hash=store_hash).first()
    if store is None:
        return "Store not found!", 401

    # Lookup user and delete it
    bc_user_id = user_data['user']['id']
    user = User.query.filter_by(bc_id=bc_user_id).first()
    if user is not None:
        storeuser = StoreUser.query.filter_by(user_id=user.id, store_id=store.id).first()
        db.session.delete(storeuser)
        db.session.commit()

    return flask.Response('Deleted', status=204)

#
#API endpoints
#
@app.route('/echo', methods = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'])
def api_echo():
    if request.method == 'GET':
        return "ECHO: GET\n"

    elif request.method == 'POST':
        return "ECHO: POST\n"

    elif request.method == 'PATCH':
        return "ECHO: PACTH\n"

    elif request.method == 'PUT':
        return "ECHO: PUT\n"

    elif request.method == 'DELETE':
        return "ECHO: DELETE"

#Calls WOYC API based on paramaters.
@app.route('/WOYC/send_order', methods=['POST'])
def send_order(order, shipping, products):
    try:
        sys.stdout.write("****************** send_order Start *****************" + "\n")
        total = len(products) - 1
        items = []
        sys.stdout.write(str(order) + "\n")
        sys.stdout.write(str(shipping[0]) + "\n")
        sys.stdout.write(str(products[0]) + "\n")
        send_request = {
            "external_ref": str(order['id']),
            "external_product_id": str(products[0]['product_id']),
            "company_ref_id":'20776',
            "customer_name": shipping[0]['first_name'] + " " + shipping[0]['last_name'],
            "customer_email": shipping[0]['email'],
            # shipping info
            "shipping_address_1": shipping[0]['street_1'],
            "shipping_address_2": shipping[0]['street_2'],
            "shipping_postcode": shipping[0]['zip'],
            "shipping_country": shipping[0]['country'],
            "shipping_country_code": shipping[0]['country_iso2'],
            "shipping_carrier": "USPS",
            "shipping_method": "Standard",
            #billing info
            "billing_address_1": order['billing_address']['street_1'],
            "billing_address_2": order['billing_address']['street_2'],
            "billing_postcode": order['billing_address']['zip'],
            "billing_country": order['billing_address']['country'],
            "billing_postcode": order['billing_address']['country_iso2']
            }
        #load item orders
        while total >= 0:
            order = {
                "sku": products[total]['sku'],
                "external_ref": str(products[total]['order_id']),
                "description": products[total]['name'],
                "type": 1,
                "quantity": products[total]['quantity'],
                "external_url": app.config['APP_URL'] + '/products/' + products[total]['sku'],
                "external_thumbnail_url": app.config['APP_URL'] + '/thumbnails/' + products[total]['sku']
                }
            items.append(order)
            total -= 1
        send_request['items'] = items

        #send package
        settings = {'Content-Type':'application/json'}
        url = 'https://api-sl-2-1.custom-gateway.net/order/?k=B34BD15F58BA68E828974D69EE8'

        sys.stdout.write("****************** send_package Start *****************" + "\n")
        sys.stdout.write(str(send_request) + "\n")
        send_package = requests.post(url, json=send_request, headers=settings)
        sys.stdout.write("****************** send_package End *****************" + "\n")
        sys.stdout.write(str(send_package) + "\n")
    except Exception as e:
        sys.stdout.write(e + "\n")
    finally:
        sys.stdout.write(str("Status Code: " + send_package.status_code) + "\n")
        sys.stdout.write(str(send_package.text) + "\n")
        sys.stdout.write("****************** End *****************" + "\n")

#Calls BC API based on settings and passes send_order
@app.route('/bigcommerce/get_order', methods=['GET'])
def get_order(order_id):
    #Settings for GET REQUEST
    store_hash = '27ls85ds6i'
    order_url = 'https://api.bigcommerce.com/stores/{}/v2/orders/{}'.format(store_hash, order_id)
    ship_url = order_url + '/shippingaddresses'
    product_url = order_url + '/products'
    headers = {
        'Accept':'application/json',
        'Content-Type':'application/json',
        'X-Auth-Client':'97dt41avc2dohxzoknmm30w1hsoa3us',
        'X-Auth-Token':'1yjssyenmt9vuu9fqw2cmoi104zgoyq'
    }

    #Get Order: Call Bigcommerce API
    try:
        get_products = requests.get(product_url, headers=headers)
        products = get_products.content
        products.decode("utf-8")
        dproducts = json.loads(products)

        get_shipping = requests.get(ship_url, headers=headers)
        shipping = get_shipping.content
        shipping.decode("utf-8")
        dshipping = json.loads(shipping)

        get_order = requests.get(order_url, headers=headers)
        order = get_order.content
        order.decode("utf-8")
        dorder = json.loads(order)

        send_order(dorder, dshipping, dproducts)
    except Exception as e:
        sys.stdout.write(str(e))
    finally:
        if products != None:
            response = app.response_class(
                status=200,
                mimetype='application/json'
                )
            return response
        else:
            response = app.response_class(
                status=400,
                mimetype='application/json'
                )
            return response

#Callback API Endpoint: Activates through BC webhook that has been setup.
@app.route('/bigcommerce/message', methods=['POST'])
def message():
    sys.stdout.write("****************** LOG Start *****************" + "\n")
    post = request.get_json()
    sys.stdout.write(str(post) + "\n")
    if post['scope'] == 'store/order/created':
        get_order(post['data']['id'])

    if request.headers['Content-Type'] == 'text/plain':
        data = {}
        response = app.response_class(
            response=json.dumps(data),
            status=200,
            mimetype='application/json'
            )
        return response
    elif request.headers['Content-Type'] == 'application/json':
        data = {}
        response = app.response_class(
            response=json.dumps(data),
            status=200,
            mimetype='application/json'
            )
        return response
    elif request.headers['Content-Type'] == 'application/octet-stream':
        f = open('./binary', 'wb')
        f.write(request.data)
        f.close()
        return "Binary message written!"
    else:
        return 415

#
# App interface
#
@app.route('/')
def index():
    # Lookup user
    storeuser = StoreUser.query.filter_by(id=flask.session['storeuserid']).first()
    if storeuser is None:
        return "Not logged in!", 401
    store = storeuser.store
    user = storeuser.user

    # Construct api client
    client = BigcommerceApi(client_id=client_id(),
                            store_hash=store.store_hash,
                            access_token=store.access_token)

    # Fetch a few products
    products = client.Products.all()

    # Render page
    context = dict()
    context['products'] = products
    context['user'] = user
    context['store'] = store
    context['client_id'] = client_id()
    context['api_url'] = client.connection.host
    context['json'] = json.dumps(request.json)
    return render('index.html', context)

@app.route('/products/<sku>')
def get_image(sku):
    image = sku + '.jpeg'
    return render_template('products.html', sku=image)

@app.route('/thumbnails/<sku>')
def get_thumbnail(sku):
    thumb = sku + '.webp'
    return render_template('thumbnails.html', sku=thumb)

@app.route('/instructions')
def instructions():
    if not app.config['DEBUG']:
        return "Forbidden - instructions only visible in debug mode"
    context = dict()
    return render('instructions.html', context)

if __name__ == "__main__":
    db.create_all()
    app.run(app.config['LISTEN_HOST'], app.config['LISTEN_PORT'])
