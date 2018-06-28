
from bs4 import BeautifulSoup
import requests
import logging
# from multiprocessing.dummy import Pool as ThreadPool
import threading
import time

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(name)s :%(message)s')


class Links:
    def __init__(self, uri, load_first_page=False):
        if uri[-1] != '/': # check endsWith ( '/')
            uri = uri + '/'
        self.base_url = uri
        self.logger = logging.getLogger()
        if load_first_page:
            self.logger.info('Links init with first page')
            self.histogram = {'0': self.load_page()}
        else:
            self.histogram = {}
        self.h_lock = threading.Lock()
        self.logger.debug('init done')


    def load_page(self, url):
        self.logger.info('Loading page %s' % url)
        r = requests.get(url)
        if r.status_code != 200:
            self.logger.info('Page %s bad response %d %s' % (repr(url), r.status_code, r.reason))
            return []
        soup = BeautifulSoup(r.text, 'lxml')
        links = []
        for title in soup.find_all('h2', class_='title'):
            # title.a.string  >> name
            # title.a.get('href') >> url
            if title.a:
                links.append((title.a.string, title.a.get('href')))
        self.logger.info('Total links %d from %s' % (len(links), url))
        return links

    def get_page(self, pageNum):
        try:
            pageNum = str(pageNum)
        except Exception as e:
            self.logger.error('%s %s' %(type(e),str(e)))
            return []
        self.h_lock.acquire()
        if pageNum in self.histogram:
            self.h_lock.release()
            return self.histogram[pageNum]

        url = self.base_url + str(pageNum)
        links = self.load_page(url)
        self.histogram[pageNum] = links
        self.h_lock.release()
        return links

    def find_on_page(self, pageNum, searchTerm):
        # return list of tupled filtered headers and urls
        self.logger.debug('entered')
        self.get_page(pageNum)
        filterd_list = filter(lambda x: searchTerm in x[0], self.histogram[str(pageNum)])
        self.logger.info('exits, %d links were found on page %s' % (len(filterd_list), str(pageNum)))
        self.logger.debug('%s' % filterd_list[:10])
        return filterd_list

def test1():
    ''' argsparse build the Links, find in page'''
    head = Links('https://www.macrumors.com/')
    head.get_page(2)
    head.find_on_page(2, 'iPhone')

def test2(size = 3):
    # find multi in threads
    head = Links('https://www.macrumors.com/')

    term = 'iPhone'
    pool = []
    for page in range(size):
        pool.append(threading.Thread(target=head.find_on_page, args=(page, term)))
    for t in pool:
        t.start()


def main():
    # test1()
    test2(10)


main()