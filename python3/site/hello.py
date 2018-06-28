#!/usr/bin/python3
import cgi

import cgitb # cgi traceback

cgitb.enable(display=0, logdir='/var/log/httpd/')  #tbenable


s = '''Content-type:text/html


<html><body>
<h1>It works!</h1>'''
print (s)

form = cgi.FieldStorage()
if form.getvalue('name'):
    name = form.getvalue('name')
    print ('<h1> hi %s </h1><br />' % name)

if form.getvalue('happy'):
    print('<p>happy</p>')

if form.getvalue('sad'):
    print('<p>sad</p>')
s = """
<form method='post' action='hello.py'>
<p>Name: <input type='text' name='name'/></p>
<input type='checkbox' name='happy'/> Happy
<input type='checkbox' name='sad'/> Sad
<input type='submit' value='Submit'/> 
</form>
</br></br>
<a href="/uploadfile.html" > Next </a>
"""
print(s)



print('</body></html>')

