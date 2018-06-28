import xlrd
import sys, os
from datetime import datetime
from string import Template


class AnalyzeSheet:
    def __init__(self, xlsxpath, index=0):
        ''' loading the workbook from given path
            sheet at @index default is 0
        '''
        if not os.path.isfile(xlsxpath):
            print 'Path %s not found' % repr(xlsxpath)
            exit(0)
        self.book = xlrd.open_workbook(xlsxpath)
        self.table = []
        self.worksheet = self.book.sheet_by_index(index)
        _, data_row = self._get_cols_titles()  # The row where we stack the name of the columns
        self._load(data_row)


    def _getline(self, r):
        row = []
        for col in xrange(self.worksheet.ncols):
            row.append(self.worksheet.cell_value(r, col))
        return row

    def get_col_index(self, name):
        if name in self.first_row:
            return self.first_row.index(name)
        return -1

    def _get_cols_titles(self):
        first_row = []
        for row in xrange(self.worksheet.nrows):
            first_row = []
            for col in xrange(self.worksheet.ncols):
                if not self.worksheet.cell_value(row, col):
                    break
                first_row.append(self.worksheet.cell_value(row, col))
            if len(first_row) == self.worksheet.ncols: # all lines attached
                break
        self.first_row = first_row
        return first_row, row+1

    def _load(self, from_row, to_row=0):
        if to_row <= 0:
            to_row = self.worksheet.nrows
        if from_row >= to_row:
            return
        nrow = from_row
        for nrow in xrange(from_row, to_row):
            dic = {}
            row = self._getline(nrow)
            for i in xrange(self.worksheet.ncols):
                if 'Date' == self.first_row[i]:
                    try:
                        col_date = xlrd.xldate_as_tuple(row[i], self.book.datemode)
                        col_date = datetime(*col_date)
                    except:
                        return nrow
                    dic[self.first_row[i]] = col_date
                elif 'Campaign' == self.first_row[i]:  # last min change edit
                    dic[self.first_row[i]] = row[i].split()[0]
                elif 'Cost' == self.first_row[i]:
                    dic[self.first_row[i]] = float(row[i])
                else:
                    dic[self.first_row[i]] = row[i]
            self.table.append(dic)

        return nrow

    def _compute_app_campaign(self):
        try:
            keys = map(lambda x: (x['App'], x['Campaign']), self.table)
            keys = list(set(keys))
            inner_tmplt = Template("$App, $Camp : Total Cost:$Cost Total Installs:$Installs")
            for i in keys:
                sum = {}
                filtered = filter(lambda x: x['App'] == i[0] and x['Campaign'] == i[1], self.table)
                sum['App'] = i[0]
                sum['Camp'] = i[1]
                sum['Cost'] = reduce(lambda x, y: x + float(y), map(lambda x: x['Cost'], filtered))
                sum['Installs'] = reduce(lambda x, y: x + float(y), map(lambda x: x['Installs'], filtered))
                print inner_tmplt.safe_substitute(sum)
        except:
            pass

    def _compute_date(self):
        try:
            keys = map(lambda x: x['Date'], self.table)
            keys = list(set(keys))
            inner_tmplt = Template("$Date : Total Cost:$Cost Total Installs:$Installs")
            for i in keys:
                sum = {}
                filtered = filter(lambda x: x['Date'] == i, self.table)
                sum['Date'] = i.strftime("%Y-%m-%d")
                sum['Cost'] = reduce(lambda x, y: x + float(y), map(lambda x: x['Cost'], filtered))
                sum['Installs'] = reduce(lambda x, y: x + float(y), map(lambda x: x['Installs'], filtered))
                print inner_tmplt.safe_substitute(sum)
        except:
            pass

    def _sum(self, key):
        # can be defined and calculated at _load
        if key in self.first_row:
            return reduce(lambda x, y: x + float(y), map(lambda x: x[key], self.table))
        return 0

    def compute(self):
        '''
        loads datasheet
This script should receive one argument, which would be the input file path to analyze.
The script should open the file, parse it and print the following information:
The Total Installs and Total Cost
The Total Installs and Total Cost for each Date using the next format: "%Y-%m-%d"
The Total Installs and Total Cost for each App and Platform (iOS/Android)
        :return:
        '''
        # self.group_by = {'Date': ['Cost', 'Installs'],
        #                  'App,Camp': ['Cost', 'Installs']}  # values sould be accurate
        cost = self._sum('Cost')
        ins = self._sum('Installs')
        print 'Total Installs are: %.3f, Total Cost: %.3f' % (ins, cost)
        self._compute_app_campaign()
        self._compute_date()
        return


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        if os.path.isfile(arg):
            AnalyzeSheet(arg).compute()
        else:
            print 'File %s not found' % repr(arg)
