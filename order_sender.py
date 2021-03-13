#class that incapsulates common settings and methods of the sending orders to
#API mastermap from telegram bot.
from api import sendMessageToChat


class OrderSender:

    def __init__(self):
        self.choiced_city = ''
        self.message = ''

    def send(token, userId):
        return sendMessageToChat(token, userId, self.choiced_city, self.message)    
