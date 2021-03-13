import requests
import config


def sendMessageToChat(token, userId, cityName, message):
    r = requests.post(
        config.SEND_MESSAGE_URL,
         data = {
            'token': token,
            'userId': userId,
            'text': message,
            'messageType': 'text',
            'topic': cityName,
            'title': 'title'
        }
    )
    return r.status_code
