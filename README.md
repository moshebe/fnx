# Fnx
Simple script that automates the monitoring of your finance products in your "phoenix" ("הפניקס") account.
  

  
## Usage
First, create `.env` file with your configuration or just edit the environment on `docker-compose.yml`

| Field      | Description |
| ----------- | ----------- |
| FNX_EMAIL      | The Email that you registered with, it will be used also for getting the OTP       |
| FNX_PASS   | Password used to access to Email for receiving the OTP. If you use Gmail you can generate App Password        |
| FNX_UID   | User Identifier that you registered with|
| TELEGRAM_TOKEN   | Telegram token for your bot|
| TELEGRAM_CHAT_ID   | Telegram chat id to send the results summary to|
| TELEGRAM_DISABLED   | If set, the result won't be published to the Telegram channel|
| VERBOSE   | If set, the logger severity will be set to debug|

  

Now, you can simply run:
```
docker-compose up --remove-orphans
```