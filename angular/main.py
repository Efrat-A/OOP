
class Board:
    def __init__(self, file_path):
        FH = open(file_path, 'r')
        line1 = FH.readline()
        self.R = int(line1.split()[0])
        self.C = int(line1.split()[1])
        self.L = int(line1.split()[2])
        self.H = int(line1.split()[3])

        self.sumBoard = [[] for y in range(self.R+1)]

        file_board = FH.read()
        FH.close()

        self.board = [[0 for x in range(self.C)] for y in range(self.R)]

        for i in range(self.R):
            for j in range(self.C):
                if file_board[(self.C+1)*i + j] == 'T':
                    self.board[i][j] = 0
                else:
                    self.board[i][j] = 1

        self.calculate_sum_matrix()

    def print_board(self):
        for row in self.board:
            print row

    def calculate_sum_matrix(self):
        self.sumBoard[0] = [0 for i in range(self.C+1)]
        for i in range(len(self.sumBoard)-1):
            self.sumBoard[i+1] = [0]
            for x in self.board[i]:
                self.sumBoard[i+1].append(x)

        for i in range(self.R):
            for j in range(self.C + 1):
                self.sumBoard[i + 1][j] = self.sumBoard[i + 1][j] + self.sumBoard[i][j]

        for i in range(self.R + 1):
            for j in range(self.C):
                self.sumBoard[i][j+1] = self.sumBoard[i][j+1] + self.sumBoard[i][j]

        for row in self.sumBoard:
            print row

    def is_slice_fits(self,r1,c1,r2,c2):
        r2 += 1
        c2 += 1
        slice_size = (r2-r1) * (c2-c1)
        if slice_size > self.H:
            return False
        num_of_mushrooms_in_slice = self.sumBoard[r2][c2] - \
                                    self.sumBoard[r2][c1] - \
                                    self.sumBoard[r1][c2] + \
                                    self.sumBoard[r1][c1]
        num_of_tomatos_in_slice = slice_size - num_of_mushrooms_in_slice
        # print num_of_mushrooms_in_slice , " " , num_of_tomatos_in_slice
        return  num_of_mushrooms_in_slice >= self.L and num_of_tomatos_in_slice >= self.L


def main():
    board = Board("small.in")
    # board.print_board()
    # print board.is_slice_fits(0,0,1,1)
    # print board.is_slice_fits(1, 1, 2, 2)
    # print board.is_slice_fits(1, 1, 2, 3)
    # print board.is_slice_fits(0, 1, 1, 2)

if __name__ == '__main__':
    main()