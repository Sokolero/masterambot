#class that incapsulates common settings and methods of the sending orders to
#API mastermap from telegram bot.
from api import sendMessageToChat


class OrderSender:

    def __init__(self):
        self.choiced_city = ''
        self.message = ''

    def set_choiced_city(self, city):
        self.choiced_city = city

    def set_message(self, message):
        self.message = message        

    def send(self, token, userId):
        return sendMessageToChat(token, userId, self.choiced_city, self.message)
