
import requests
from bs4 import BeautifulSoup
import logging
from multiprocessing.dummy import Pool as ThreadPool
import threading

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(name)s :%(message)s')


class Links:  # self collection for a search Term
    def __init__(self, uri, load_first_page=False):
        if uri[-1] != '/': # check endsWith ( '/')
            uri = uri + '/'
        self.base_url = uri
        self.logger = logging.getLogger()
        if load_first_page:
            self.logger.debug('Links init with first page')
            self.histogram = {'0': self.load_page()}
        else:
            self.histogram = {}
        self.logger.debug('init done')

    def load_page(self, url):
        self.logger.info('Loading page %s' % url)
        try:
            r = requests.get(url)
            if r.status_code != 200:
                self.logger.info('Page %s bad response %d %s' % (repr(url), r.status_code, r.reason))
                return []
        except requests.exceptions.ConnectionError:
            self.logger.error('Site unavailable')
        except Exception as ex:
            self.logger.error('%s' % type(ex))
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
            self.logger.error('%s %s' % (type(e), str(e)))
            return []
        try:
            if pageNum in self.histogram:
                return self.histogram[pageNum]
            url = self.base_url + str(pageNum)
            links = self.load_page(url)
            # self.h_lock.acquire()
            self.histogram[pageNum] = links #[0]
            # self.h_lock.release()
            return links
        finally:
            pass
            # self.h_lock.release()
    #
    # def find_on_page(self, pageNum, searchTerm):
    #     # return list of tupled filtered headers and urls
    #     page_results = self.get_page(pageNum)
    #     filterd_list = filter(lambda x: searchTerm in x[0], page_results)
    #     self.logger.info('%d links were found on page %s' % (len(filterd_list), str(pageNum)))
    #     return filterd_list

    def collect(self, search_term, pages):
        ''' going through url/0... url/pages-1
        lookup in all titles ( h2 class_=title) in page which has a url
        return a collection of title-link tuple's list which contains the search_term in the title
        '''
        pool = ThreadPool(pages)
        pars = []
        # url = 'https://www.macrumors.com/'
        for n in range(pages):
            # pars.append(self)
            # pars.append(n)
            # pars.append(search_term)
            pars.append((self, n, search_term))
        links = pool.map(find_on_page, pars, 3)
        pool.close()
        pool.join()
        links = reduce(lambda x, y: x + y, links)
        return links


def find_on_page(params):
# def find_on_page(links, pageNum, searchTerm):
    '''
    params =  links, pageNum, searchTerm
    '''
    links, pageNum, searchTerm = params
    # return list of tupled filtered headers and urls
    page_results = links.get_page(pageNum)
    filterd_list = filter(lambda x: searchTerm in x[0], page_results)
    links.logger.info('%d links were found on page %s' % (len(filterd_list), str(pageNum)))
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
    collection = head.collect(term, 100)
    for i in collection:
        print '%s   %s' % (i[0], i[1])
    # pool = []
    # for page in range(size):
    #     pool.append(threading.Thread(target=head.find_on_page, args=(page, term)))
    # for t in pool:
    #     t.start()

def main():
    #test1()
    test2(10)
    test3()

def test3():
    import random
    print random.randint(0, 10)


main()
