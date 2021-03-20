import requests
import config


def sendMessageToChat(token, userId, cityName, message):
    data = {
       'token': token,
       'userId': userId,
       'text': message,
       'messageType': 'text',
       'topic': cityName,
       'title': 'title'
    }
    print(data)
    r = requests.post(config.SEND_MESSAGE_URL, data=data)
    print('sended!')
    return r.status_code
