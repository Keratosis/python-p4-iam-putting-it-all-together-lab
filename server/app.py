#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from flask import jsonify

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')
        image_url = json_data.get('image_url')
        bio = json_data.get('bio')

        # Validate the input
        if not username or not password:
            return jsonify({'error': 'Username and password are required.'}), 422

        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'Username is already taken.'}), 422

        # Create a new user
        new_user = User(username=username, password_hash=password, image_url=image_url, bio=bio)
        db.session.add(new_user)
        db.session.commit()

        # Save the user's ID in the session object
        session['user_id'] = new_user.id

        # Return the user object as JSON
        user_data = {
            'id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }
        return jsonify(user_data), 201

class CheckSession(Resource):
    def get(self):
        # Check if the user is logged in
        user_id = session.get('user_id')
        if user_id:
            # Retrieve the user from the database
            user = User.query.get(user_id)
            if user:
                # Return the user object as JSON
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
                return jsonify(user_data), 200

        # If the user is not logged in, return an error message
        return jsonify({'error': 'Unauthorized.'}), 401


class Login(Resource):
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        # Validate the input
        if not username or not password:
            return jsonify({'error': 'Username and password are required.'}), 401

        # Retrieve the user from the database
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password is valid
        if user and user.authenticate(password):
            # Save the user's ID in the session object
            session['user_id'] = user.id

            # Return the user object as JSON
            user_data = {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }
            return jsonify(user_data), 200

        # If the username or password is invalid, return an error message
        return jsonify({'error': 'Invalid username or password.'}), 401

class Logout(Resource):
    def delete(self):
        # Check if the user is logged in
        if 'user_id' in session:
            # Remove the user's ID from the session object
            session.pop('user_id')

            # Return an empty response
            return {}, 204

        # If the user is not logged in, return an error message
        return jsonify({'error': 'Unauthorized.'}), 401
    
    
class RecipeIndex(Resource):
    def get(self):
        # Check if the user is logged in
        if 'user_id' in session:
            # Retrieve all recipes from the database
            recipes = Recipe.query.all()

            # Prepare the response data
            recipe_data = []
            for recipe in recipes:
                recipe_data.append({
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username,
                        'image_url': recipe.user.image_url,
                        'bio': recipe.user.bio
                    }
                })

            # Return the recipes as JSON
            return jsonify(recipe_data), 200

        # If the user is not logged in, return an error message
        return jsonify({'error': 'Unauthorized.'}), 401

    def post(self):
        # Check if the user is logged in
        if 'user_id' in session:
            json_data = request.get_json()
            title = json_data.get('title')
            instructions = json_data.get('instructions')
            minutes_to_complete = json_data.get('minutes_to_complete')

            # Validate the input
            if not title:
                return jsonify({'error': 'Title is required.'}), 422
            if not instructions or len(instructions) < 50:
                return jsonify({'error': 'Instructions must be at least 50 characters long.'}), 422

            # Create a new recipe and associate it with the logged-in user
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']
            )
            db.session.add(recipe)
            db.session.commit()

            # Prepare the response data
            recipe_data = {
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username,
                    'image_url': recipe.user.image_url,
                    'bio': recipe.user.bio
                }
            }

            # Return the new recipe as JSON
            return jsonify(recipe_data), 201

        # If the user is not logged in, return an error message
        return jsonify({'error': 'Unauthorized.'}), 401







api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
