#!/env/bin/python3.6
import telebot
from telebot import types

import config
from order_sender import OrderSender


#===========#
def main():
    bot = telebot.TeleBot(config.TOKEN)
    sender = OrderSender()

    @bot.message_handler(func=lambda message: message.chat.id not in config.users)
    def reject_message(message):
        print('Reject')
        bot.reply_to(message, 'У вас нет прав доступа.')

    @bot.message_handler(commands=['start'])
    def accept_message(message):
        print(message.chat)
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

    @bot.message_handler(content_types=['text'])
    def handle_city_choice(message):
        if message.text in config.CITY_LIST:
            sender.choiced_city = message.text
            bot.reply_to(message, 'Сейчас вы размещаете объявления в {}'.format(sender.choiced_city))
        elif message.text not in config.CITY_LIST and sender.choiced_city == '':
            bot.reply_to(message, 'Выберите городе, где желаете размещать объявления')
        elif message.text:
            #handling of sending text data somewhere:
            sender.order = message.text
            # sender.send()
            bot.reply_to(message, 'Ваше объявление успешно размещено в {}'.format(sender.choiced_city))


    bot.polling()


#-----------------------------------------------
if __name__ == '__main__':
    main()
