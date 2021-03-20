class User:
    def __init__(self):
        self.token = None
        self.userId = None

    def set_token(self, token):
        self.token = token

    def set_userId(self, userId):
        self.userId = userId     

    def get_token(self):
        return self.token

    def get_userId(self):
        return self.userId
