#!/env/bin/python3.6
import os
import logging
import time
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import flask
import json

import telebot
from telebot import types

import config
from order_sender import OrderSender
from api import sendMessageToChat


# ======= Bot init =============================================================
bot = telebot.TeleBot(config.BOT_TOKEN)
sender = OrderSender()

#======== FLASK app ============================================================
app = flask.Flask(__name__)
app.secret_key = '123456789'

# --------WEBHOOK---------------------------------------------------------------
# index route responding status_code 200
@app.route('/', methods=['GET', 'HEAD'])
def index():
    return ''

# Processing webhook calls from Telegram server
@app.route('/webhook', methods=['POST'])
def webhook():
    if flask.request.headers.get('content-type') == 'application/json':
        json_string = flask.request.get_data().decode('utf-8')
        update = telebot.types.Update.de_json(json_string)
        bot.proccess_new_updates([update])
        return ''
    else:
        flask.abort(403)


# ---------Authenticatiion in Google OAuth2 and Masteram routes-----------------
#authorization in masteram app.
@app.route('/masteramauth')
def masteramauth():
    credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])
    r = requests.post(config.AUTH_URL, data = {'IdToken': credentials.id_token})
    if r.status_code == 200:
        userId = r.json()['id']
        token = r.json()['userToken']
        flask.session['user'] = {
            'token': token,
            'userId': userId,
        }
        print(flask.session['user'])
        return 'Авторизация на Masteram успешно выполнена.'
    return 'Авторизация не выполнена.'


#Authorization view for Google OAuth2. This route url sends to Telegram bot client
@app.route('/auth', methods=['POST', 'GET'])
def authorize():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes = [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ]
    )
    flow.redirect_uri = flask.url_for('callback', _external=True)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
    )
    flask.session['state'] = state
    return flask.redirect(authorization_url)


#Callback route after consent to authenticate in masteram app
@app.route('/callback', methods=['POST', 'GET'])
def callback():
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes = [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'openid'
        ],
        state=state
    )
    flow.redirect_uri = flask.url_for('callback', _external=True)
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('masteramauth'))

# Revoke Google OAuth2 token to log out
@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + print_index_table())
  else:
    return('An error occurred.' + print_index_table())


# Clear token in flask session
@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          print_index_table())

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes,
        'id_token': credentials.id_token,
    }

def print_index_table():
  return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')

# ---------BOT HANDLERS----------------------------------------------
# Check of Telegram user permissions
@bot.message_handler(func=lambda message: message.chat.id not in config.users)
def reject_message(message):
    print('Reject')
    bot.reply_to(message, 'У вас нет прав доступа.')

@bot.message_handler(commands=['start'])
def accept_message(message):
    bot.send_message(message.chat.id, 'Начинаем: {}'.format(config.HELP_MESSAGE))

@bot.message_handler(commands=['help'])
def help_message(message):
    bot.reply_to(message, config.HELP_MESSAGE)

@bot.message_handler(commands=['cities'])
def send_keyboard(message):
    print('cities request')
    markup = types.ReplyKeyboardMarkup(row_width=2, one_time_keyboard=True)
    buttons = []
    for city in config.CITY_LIST:
        buttons.append(types.KeyboardButton(city))
    markup.add(*buttons)
    bot.send_message(message.chat.id, 'В каком городе размещать объявления?', reply_markup=markup)

# main messages handler
@bot.message_handler(content_types=['text'])
def handle_city_choice(message):
    if message.text in config.CITY_LIST:
        sender.choiced_city = message.text
        bot.reply_to(message, 'Сейчас вы размещаете объявления в {}'.format(sender.choiced_city))
    elif message.text not in config.CITY_LIST and sender.choiced_city == '':
        bot.reply_to(message, 'Выберите городе, где желаете размещать объявления командой  /cities')
    elif message.text:
        #handling of sending text data somewhere:
        sender.message = message.text
        print(flask.session['user']['token'])
        status_code = sender.send(
            flask.session['user']['token'],
            flask.session['user']['userId'],
        )
        if status_code == 200:
            bot.reply_to(message, 'Ваше объявление успешно размещено в {}'.format(sender.choiced_city))
        else:
            bot.reply_to(message, 'При размещении объявления возникли проблемы')

# --------PREPARE WEBHOOK--------------------------------
bot.remove_webhook()
time.sleep(0.1)
bot.set_webhook(
    url=config.WEBHOOK_URL_BASE + config.WEBHOOK_URL_PATH,
    certificate=open(config.WEBHOOK_SSL_CERT, 'r')
)

# =================================RUN==========================================
if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(
        config.WEBHOOK_HOST,
        config.WEBHOOK_PORT,
        ssl_context=(config.WEBHOOK_SSL_CERT, config.WEBHOOK_SSL_PRIV),
        debug=True
    )
