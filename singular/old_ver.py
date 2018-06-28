import xlrd
import sys, os
from datetime import datetime
from string import Template


class AnalyzeSheet:
    def __init__(self, xlsxpath):
        self.book = xlrd.open_workbook(xlsxpath)
        self.table = []
        # self.group_by = {}
        # self.groups = {}

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
        if to_row == 0:
            to_row = self.worksheet.nrows
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
                        if 'Totals' == row[i]:
                            costs, installs = self.get_col_index('Cost'), self.get_col_index('Installs')
                            if costs > 0 and installs > 0:
                                print 'The Total Installs are: %d and Total Cost: %d' % (row[costs], row[installs])
                        return nrow
                    dic[self.first_row[i]] = col_date
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

    def compute(self, index=0):
        '''
        loads datasheet
This script should receive one argument, which would be the input file path to analyze.
The script should open the file, parse it and print the following information:
The Total Installs and Total Cost
The Total Installs and Total Cost for each Date using the next format: "%Y-%m-%d"
The Total Installs and Total Cost for each App and Platform (iOS/Android)
        :return:
        '''
        self.group_by = {'Date': ['Cost', 'Installs'],
                         'App,Camp': ['Cost', 'Installs']}  # values sould be accurate
        self.worksheet = self.book.sheet_by_index(index)
        _, data_row = self._get_cols_titles()  # The row where we stack the name of the columns
        self._load(data_row)
        self._compute_app_campaign()
        self._compute_date()
        return


if __name__ == '__main__':
    path = '/home/ea/offwork/singular/pure/report.xlsx'
    if len(sys.argv) == 1:
        if os.path.isfile(path):
            print 'No path given, Using default path'
            AnalyzeSheet(path).compute()
        else:
            print 'No path given'
            exit(1)
    for arg in sys.argv[1:]:
        if os.path.isfile(arg):
            AnalyzeSheet(path).compute()



