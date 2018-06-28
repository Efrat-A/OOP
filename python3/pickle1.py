import pickle

dict1 = {'a': 100, 'b': 200,'c':300}
list1 = [ 400,500,600]
print(dict1)
print(list1)

f = open('save.pkl', 'wb')
pickle.dump(dict1, f, pickle.HIGHEST_PROTOCOL)
pickle.dump(list1, f, pickle.HIGHEST_PROTOCOL)
f.close()

print ('-'*10)

inf = open('save.pkl', 'rb')
dict2 = pickle.load(inf)
list2 = pickle.load(inf)
print(dict2)
print(list2)
inf.close()
