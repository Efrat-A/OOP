
from string import Template

class MyTemplate(Template):
    delimiter = '#'

def Main():
    cart = [ 
            dict(item='coke',price=8, qty=2),
            dict(item='cake',price=21, qty=3),
            dict(item='fish',price=32, qty=4),
            dict(item='banana',price=1, qty=10),
            ]
    #t = Template(" $qty x $item = $price")
    #t = MyTemplate(" #qty x #item = #price")
    t = MyTemplate("#qty x #item = #{price}$")
    total = 0
    print ("Cart:")
    for data in cart:
        print (t.safe_substitute(data))
        total += data['price']
    print (total)
    return 0
if __name__=='__main__':
    exit(Main())
