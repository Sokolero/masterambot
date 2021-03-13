# from googleapiclient.discovery import build

# from google_auth_oauthlib.flow import InstalledAppFlow
#
# service = build('drive', 'v3')
# service.close()
#
# # with build('drive', 'v3') as service:
# #     pass
#
# flow = InstalledAppFlow.from_client_secrets_file(
#     'client_secrets.json',
#     scopes=['profile', 'email']
# )
#
# flow.run_local_server()
import google.oauth2.credentials
import google_auth_oauthlib.InstalledAppFlow

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    'client_secret.json',
    scopes = ['https://g']
)
