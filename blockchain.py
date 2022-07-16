from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import sys



class testClass:
    string = None


    def __init__(self, init_string):
        self.string = init_string


    def __repr__(self):
        return str(self.string)



class CBlock:
    data = None
    previousHash = None
    previousBlock = None

    
    def __init__(self, data, previousBlock):
        self.data = data
        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()
            self.previousBlock = previousBlock


    def computeHash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.data), 'utf-8'))
        hash = digest.finalize()
        return hash


    def __repr__(self):
        return str(self.data)



if __name__ == '__main__':
    root = CBlock('I am root', None)
    B1 = CBlock('I am B1', root)
    B2 = CBlock('I am B1->B2', B1)
    B3 = CBlock(1234, B2)
    B4 = CBlock(testClass('I am B4'), B2)
    B5 = CBlock(testClass('I am B4->B5'), B4)


    for b in [root, B1, B2, B3, B4, B5]:
        print("Checking: "+str(b))
        if b.previousBlock != None:
            if b.previousBlock.computeHash() == b.previousHash:
                print("Hash confirmed")
            else:
                print("Hash FAILED")
        else:
            print("Root node")

    print("testing with a fake node")
    BF = CBlock('fake node', root)
    if BF.computeHash() == B1.computeHash():
        print("fake node accepted")
    else:
        print("fake node failed")
        
    print("testing with tampering")
    B3.data = 1234
    if B4.previousBlock.computeHash() != B3.computeHash():
        print("Tampering detected")
    else:
        print("WARNING: Tampering not detected")