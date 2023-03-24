import requests
from bs4 import BeautifulSoup
import imaplib
import email
import time
import re
from datetime import datetime
import os
import sys
import logging

file_handler = logging.FileHandler(filename='/tmp/fnx.log')
stdout_handler = logging.StreamHandler(sys.stdout)
handlers = [file_handler, stdout_handler]

if os.environ.get('VERBOSE'):
    log_level = logging.DEBUG
else:
    log_level = logging.INFO

logging.basicConfig(
    level=log_level,
    format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s',
    handlers=handlers
)

logger = logging.getLogger('fnx')

def wait_for_activation_code(email, password, new_email_threshold = 60, retries = 5, interval = 5):
    code = None
    count = 0
    while count < retries:
        code = search_code_in_inbox(email, password, new_email_threshold)
        if code is not None:
            return code
        logger.debug('code was not found yet, will try again in {} seconds...'.format(interval))
        time.sleep(interval)
        count += 1
    return None

def search_code_in_inbox(user_email, password, new_email_threshold):
    codes = []
    code = None
    imap_object = imaplib.IMAP4_SSL('imap.gmail.com')
    imap_object.login(user_email, password)

    try:
        status, response = imap_object.select('INBOX')
        if 'OK' not in status:
            raise Exception('select inbox')
        
        status, response = imap_object.search(None, '(UNSEEN FROM "FnxNoReplay@fnx.co.il")')
        if 'OK' not in status:
            raise Exception('search fnx address in inbox')

        emails = response[0].decode().split()    
        if not emails:
            return None
        
        for num in emails:
            fetch_status, data = imap_object.fetch(num, '(RFC822)')
            if 'OK' not in fetch_status:
                continue
        
            msg = email.message_from_string(data[0][1].decode('utf-8'))    

            received_at = datetime.strptime(msg['Date'], '%a, %d %b %Y %H:%M:%S %z').replace(tzinfo=None)
            elapsed_seconds = (datetime.now()-received_at).total_seconds()
            if new_email_threshold > 0 and elapsed_seconds >= new_email_threshold:
                logger.debug('old activation code email found, ignore it (elapsed: {}s) code: {}'.format(elapsed_seconds, re.findall(r' \d+', msg.get_payload(decode=True).decode('utf-8'))))
                continue
        
            logger.debug('relevant email may be found, elapsed: {}s threshold: {}s'.format(elapsed_seconds, new_email_threshold))
                
            while msg.is_multipart():
                logger.debug('message is multiple, entering nesting level')
                msg = msg.get_payload(0)

            payload = msg.get_payload(decode=True).decode('utf-8')
            nums = re.findall(r' \d+', payload)
            if len(nums) <= 0:
                raise Exception('could not find activation code in content')
        
            code = nums[0]
            if code is None:
                raise Exception('could not find code in email')

            codes.append(code.strip())
                
    except Exception as e:
        logger.error('failed searching activation code in email, error: {}'.format(e))
    
    finally:
        imap_object.close()
        imap_object.logout()

    if not codes:
        return None

    return codes[-1]

def get_verification_token(session, url):   
    r = session.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')
    csrf_token = soup.find('input', {'name': '__RequestVerificationToken'}).get('value')
    cookie_token = session.cookies.get_dict()['__RequestVerificationToken_L2ZueA2']
    return csrf_token, cookie_token

def get_field_numeric_value(fields_positions, values, field_name):
    position = fields_positions[field_name]
    value = values[position]
    return int(value.replace(',', ''))

def parse_policy_status(fields_positions, values):
    return "\n".join(['{} = {}'.format(name, values[index])  for (name, index) in fields_positions.items()])    

def parse_balance(content):
    fields = {
        'balance': 5,
        'deposits': 6,
        'profit': 8,
        'return': 9
    }
    trs = BeautifulSoup(content, 'html.parser').find_all('tr')
    trs_len = len(trs)
    if trs_len < 2:
        print(content)
        raise Exception('invalid content, expected at least two table rows but got: {}'.format(trs_len))
    
    if trs_len == 2:
        return parse_policy_status(fields, trs[1].text.splitlines())
    
    result = ''
    total_balance = 0
    total_deposits = 0
    for i in range(1, trs_len):
        tr = trs[i].text.splitlines()
        policy_status = parse_policy_status(fields, tr)
        total_balance += get_field_numeric_value(fields, tr, 'balance')
        total_deposits += get_field_numeric_value(fields, tr, 'deposits')
        result += policy_status
        result += "\n------------------\n"            
    
    total_profit = total_balance - total_deposits
    total_return = (total_profit / total_deposits) * 100
    return result + f"""Total:
balance: {total_balance:,}
deposits: {total_deposits:,}
profit: {total_profit:,}
return: {total_return:.2f}%
"""

def fetch_data(uid, user_email, password):
    session = requests.Session()

    csrf_token, cookie_token = get_verification_token(session, 'https://myinfo.fnx.co.il/Fnx/MyZone/Registration/Registration')
    logger.debug('token were found, csrf: {} cookie: {}'.format(csrf_token, cookie_token))

    headers = {
    "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
    "Host": "myinfo.fnx.co.il",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:83.0) Gecko/20100101 Firefox/83.0",    
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",    
    "Origin": "https://myinfo.fnx.co.il",    
    }
    data = "__RequestVerificationToken={token}&UserIdentity={uid}&SelectedIdentityType=0&CommissionedId=&SelectedOTPIdentificationType=1&inputUserText={email}&UserNumberPhone=&UserNumberEmail={email}&g-recaptcha-response=&X-Requested-With=XMLHttpRequest".format(
        token=csrf_token,
        uid=uid,
        email=user_email
    )
    r = session.post('https://myinfo.fnx.co.il/fnx/MyZone/Registration/Registration/CheckValidateUser', data=(data), headers=headers, cookies={'__RequestVerificationToken_L2ZueA2': cookie_token})    
    if r.status_code != 200:        
        raise Exception('failed on /CheckValidateUser status: {}'.format(r.status_code))        

    activation_code = wait_for_activation_code(user_email, password)
    logger.debug('found activation code: {}'.format(activation_code))
    if activation_code is None:
        raise Exception('failed getting the activation code')        

    csrf_token, cookie_token = get_verification_token(session, 'https://myinfo.fnx.co.il/fnx/MyZone/Registration/Registration/Otp')
    data = "__RequestVerificationToken={token}&SecretCode={code}".format(
        token=csrf_token,
        code=activation_code,
        email=user_email
    )    
    r = session.post('https://myinfo.fnx.co.il/fnx/MyZone/Registration/Registration/DoLogin', data=(data), headers=headers)    
    if r.status_code != 302 and r.status_code != 200:
        raise Exception('failed on /DoLogin status: {}'.format(r.status_code))        
    
    r = session.get('https://myinfo.fnx.co.il/fnx/MyZone/Insurance/FinancialProducts', headers=headers)
    if r.status_code != 200:
        raise Exception('failed on /FinancialProducts status: {}'.format(r.status_code))        
    
    return parse_balance(r.text)
    
def publish_result(content):
    if os.environ.get('TELEGRAM_DISABLED'):
        return
    tg_token = os.environ.get('TELEGRAM_TOKEN')
    if not tg_token:
        raise Exception('missing telegram token')
    
    tg_chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    if not tg_chat_id:
        raise Exception('missing telegram chat id')
    
    res = requests.get("https://api.telegram.org/bot{token}/sendMessage?chat_id={chat}&text={text}".format(token=tg_token, chat=tg_chat_id, text=content))
    if res.status_code != 200:
        raise Exception('unable to send telegram notification, status: {} message: {}'.format(res.status_code, res.text))

    logger.debug('content was publish on telegram successfully')

try:
    logger.info('starting...')

    user_email = os.environ.get('FNX_EMAIL')
    if not user_email:
        raise Exception('email was not set')

    password = os.environ.get('FNX_PASS')
    if not password:
        raise Exception('password was not set')

    uid = os.environ.get('FNX_UID')
    if not password:
        raise Exception('user id was not set')

    account_data = fetch_data(uid, user_email, password)
    logger.debug("successfully fetch account's information: {}".format(account_data))

    publish_result(account_data)

    logger.info('done.')
except Exception as e:
    logger.error(e)
