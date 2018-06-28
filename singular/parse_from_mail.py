import sys, os
import imaplib
import email
from script import AnalyzeSheet


def find_Singular_in_inbox(gaddress, gpass):
    ''' find this email sent from me with the subject "Singular Python Exercise" '''
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(gaddress, gpass)

    t, long = mail.select("inbox")  # connect to inbox.
    mail.response('EXISTS')

    result, data = mail.search(None, '(FROM "Yuval Carmel" SUBJECT "Singular Python Exercise")')

    ids = data[0]  # data is a list.
    id_list = ids.split()  # ids is a space separated string
    latest_email_id = id_list[-1]  # get the latest

    result, data = mail.fetch(latest_email_id, "(RFC822)")  # fetch the email body (RFC822)             for the given ID

    email_body = data[0][1]
    mail = email.message_from_string(email_body)
    if mail.get_content_maintype() != 'multipart':
        return

    for part in mail.walk():
        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
            att_path = '/tmp/file.xlsx'
            if not os.path.isfile(att_path):
                with open(att_path, 'w') as f:
                    f.write(part.get_payload(decode=True))
                break
    # mail.logout()
    AnalyzeSheet(att_path).compute()
    os.remove(att_path)


if __name__ == '__main__':
    if not len(sys.argv) == 3:
        print 'Expecting 2 arguments, username and password'
        exit(1)
    mail_account = sys.argv[1]
    passwd = sys.argv[2]
    find_Singular_in_inbox(mail_account, passwd)
