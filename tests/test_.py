import requests
from requests.auth import HTTPBasicAuth, _basic_auth_str
import json

token = ''
base_url = 'http://127.0.0.1:5000'


def login(username, password):
    path = '/login'
    req_url = base_url + path
    response = requests.post(req_url, auth=(username, password))
    global token
    token = response.json()['token']
    assert response.status_code == 200


def view_user():
    path = '/users'
    req_url = base_url + path
    response = requests.get(req_url, headers={'x-access-token': token})
    assert response.status_code == 200


def create_user(payload={}):
    path = '/create_user'
    req_url = base_url + path
    response = requests.post(req_url, headers={'x-access-token': token}, json=payload)
    assert response.status_code == 201


def add_book(payload={}):
    path = '/book/add'
    req_url = base_url + path
    response = requests.post(req_url, headers={'x-access-token': token}, json=payload)
    assert response.status_code == 201


def search_book(payload={}):
    path = '/books'
    req_url = base_url + path
    response = requests.post(req_url, headers={'x-access-token': token}, json=payload)
    assert response.status_code == 200


def view_books():
    path = '/books'
    req_url = base_url + path
    response = requests.get(req_url, headers={'x-access-token': token})
    assert response.status_code == 200


# if __name__ == '__main__':
#     login('su', '123456')
#     view_user()
#     create_user({'username': 'Chandra', 'password': '123456'})
#     add_book({'isbn': '123-93HFGD-09JDH', 'name': 'Origin', 'author': 'Dan Brown'})
#     search_book({'name': 'rig'})
#     view_books()
