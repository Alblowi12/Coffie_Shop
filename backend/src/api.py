import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS
from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)


db_drop_and_create_all()


@app.route('/drinks', methods=['GET'])
def get_drinks():
    try:
        dnk = Drink.query.all()

        return jsonify({
            'success': True,
            'drinks': [dn.short() for dn in dnk]
        })
    except:
        abort(404)


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drinks_detail(jwt):
    try:
        dnk = Drink.query.all()

        return jsonify({
            'success': True,
            'drinks': [dn.long() for dn in dnk]
        }), 200
    except:
        abort(404)


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def post_new_drinks(jwt):
    body = request.get_json()

    if not ('title' in body and 'recipe' in body):
        abort(422)

    tilt = body.get('title')
    recp = body.get('recipe')
    try:
        drink = Drink(title=tilt, recipe=json.dumps(recp))
        drink.insert()
        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200

    except:
        abort(422)


@app.route('/drinks/<id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(jwt, id):
    drink = Drink.query.get(id)

    if drink:
        try:
            body = request.get_json()

            tilt = body.get('title')
            recp = body.get('recipe')

            if tilt:
                drink.title = tilt
            if recp:
                drink.recipe = recp

            drink.update()

            return jsonify({
                'success': True,
                'drinks': [drink.long()]
            })
        except:
            abort(422)
    else:
        abort(404)


@app.route('/drinks/<id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(jwt, id):
    drink = Drink.query.get(id)

    if drink:
        try:
            drink.delete()

            return jsonify({
                'success': True,
                'delete': id,
            }), 200
        except:
            abort(422)
    else:
        abort(404)


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
           "success": False,
           "error": 422,
           "message": "unprocessable"
            })


@app.errorhandler(404)
def not_found(error):
    return jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404


@app.errorhandler(AuthError)
def handle_auth_errors(x):
    return jsonify({
        'success': False,
        'error': x.status_code,
        'message': x.error
    }), 404


@app.errorhandler(AuthError)
def handle_auth_errors_401(x):
    return jsonify({
        'success': False,
        'error': x.status_code,
        'message': x.error
    }), 401
