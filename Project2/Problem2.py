from Crypto.Hash import SHA256
import random
import string

def hash(data):
    h = SHA256.new()
    h.update(data.encode("utf-8"))
    return h.hexdigest()

class MerkleTree:
    def __init__(self, n=0):
        self.n = n
        self.root = 0
        self.filenames = []
        self.leaves = []
        self.levels = []

    # Create tree that authenticates files in the list and output the root of the tree.
    def create_tree(self, file_list):
        for file in file_list:
            self.filenames.append(file)
            self.leaves.append(hash(file))

        self.build_tree()
        return self.levels[0][0]

    # Read file at position i, as well as the sibling nodes on the path from position i to the root.
    def read_file(self, i):
        file = i
        siblings_list = []
        for x in range(len(self.levels) - 1, 0, -1):
            index = i - 1 if i % 2 else i + 1
            node_type = "l" if i % 2 else "r"
            data = self.levels[x][index]
            siblings_list.append({node_type: data})
            i = int(i / 2.)
        return (self.filenames[file], siblings_list)

    # Update the file in position i with f and update the stored root.
    # Output the new root value.
    def write_file(self, i, file):
        self.filenames[i] = file
        self.leaves[i] = hash(file)
        self.build_tree()
        return self.levels[0][0]

    # Verify that the file at position i is valid given the current root of the tree.
    # Output a boolean value (True if the file is valid and False otherwise).
    def check_integrity(self, i, file, siblings_list):
        # Check that self.root matches root computed from the returned path
        current_root = self.levels[0][0]
        file_hash = hash(file)
        h = file_hash
        for sibling in siblings_list:
            if 'l' in sibling:
                h = hash(sibling['l'] + h)
            else:
                h = hash(h + sibling['r'])

        return h == current_root

    def build_tree(self):
        self.levels = [self.leaves, ]
        while 1 < len(self.levels[0]):
            level = []
            for left_node, right_node in zip(self.levels[0][0:self.n:2], self.levels[0][1:self.n:2]):
                level.append(hash(left_node + right_node))
            self.levels = [level, ] + self.levels

if __name__ == "__main__":
    n = 32
    mt = MerkleTree(n)
    file_list = []
    for i in range(0, n):
        file_list.append("filename" + str(i))
    root = mt.create_tree(file_list)
    print("Root Hash:" + str(root))

	# read 5 valid files
    for pos in range(32):
        file, siblings_list =  mt.read_file(pos)
        valid = mt.check_integrity(pos, file, siblings_list)
        assert (file == file_list[pos] and valid == True)

	# read 5 invalid files
    for pos in range(5):
        file, siblings_list =  mt.read_file(pos)
        file = ''.join(random.choices(string.ascii_letters, k=random.randint(6, 16)))
        valid = mt.check_integrity(pos, file, siblings_list) 
        assert (valid == False)

	# write 5 files
    for pos in range(5):
        new_file = ''.join(random.choices(string.ascii_letters, k=random.randint(6, 16)))
        mt.write_file(pos, new_file)

    	# Read file and check integrity
        file, siblings_list =  mt.read_file(pos)
        valid = mt.check_integrity(pos, file, siblings_list) 
        assert (file == new_file and valid == True)
