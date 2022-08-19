#transaction.py

from ctypes import sizeof
from doctest import OutputChecker
import signatures

class Tx:
    inputs = None
    outputs = None
    signatures = None
    required = None
    in_amount = None
    out_amount = None

    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.signatures = []
        self.required = []
        self.in_amount = 0
        self.out_amount = 0

    def add_input(self, from_addr, amount):
        self.inputs.append(from_addr)
        self.required.append(from_addr)
        self.in_amount = amount

    def add_output(self, to_addr, amount):
        self.outputs.append(to_addr)
        self.out_amount = self.out_amount + amount

    def add_required(self, addr):
        self.required.append(addr)

    def sign(self, private_key):
        if(self.out_amount <= 0 or self.in_amount <= 0):
            #print("Error: amount >= 0")
            pass
        elif(self.in_amount - self.out_amount < 0):
            #print("in-out < 0")
            pass
        else:
            self.signatures.append(signatures.sign(str(self.out_amount).encode(), private_key))

    def is_valid(self):
        if(len(self.required) != len(self.signatures) ):
            return False

        for i in range(len(self.required)):
            check = signatures.verify(str(self.out_amount).encode(), self.signatures[i], self.required[i])
            if check == False:
                return False
        return True

if __name__ == "__main__":
    private_key1, public_key1 = signatures.generate_keys()
    private_key2, public_key2 = signatures.generate_keys()
    private_key3, public_key3 = signatures.generate_keys()
    private_key4, public_key4 = signatures.generate_keys()

    #test single transactions
    Tx1 = Tx()
    Tx1.add_input(public_key1, 1)
    Tx1.add_output(public_key2,1)
    Tx1.sign(private_key1)

    #test transaction to multiple recipients
    Tx2 = Tx()
    Tx2.add_input(public_key1, 2)
    Tx2.add_output(public_key2, 1)
    Tx2.add_output(public_key3,1)
    Tx2.sign(private_key1)

    #test escrow transaction
    Tx3 = Tx()
    Tx3.add_input(public_key3, 1.2)
    Tx3.add_output(public_key1, 1.1)
    Tx3.add_required(public_key4)
    Tx3.sign(private_key3)
    Tx3.sign(private_key4)

    #verify tests
    i=0
    for t in [Tx1, Tx2, Tx3]:
        i=i+1
        if t.is_valid():
            print("Tx"+str(i)+" success")
        else:
            print("Tx"+str(i)+" failed")

    
    #sign with wrong key
    Tx4 = Tx()
    Tx4.add_input(public_key1, 1)
    Tx4.add_output(public_key2,1)
    Tx4.sign(private_key2)

    #Escrow not signed by arbiter 
    Tx5 = Tx()
    Tx5.add_input(public_key3, 1.2)
    Tx5.add_output(public_key1, 1.1)
    Tx5.add_required(public_key4)
    Tx5.sign(private_key3)

    #Two inputs but only signed by one
    Tx6 = Tx()
    Tx6.add_input(public_key3, 1)
    Tx6.add_input(public_key4, 0.1)
    Tx6.add_output(public_key1, 1.1)
    Tx6.sign(private_key3)

    #Output exceeds input
    Tx7 = Tx()
    Tx7.add_input(public_key1, 2.5)
    Tx7.add_output(public_key2, 2.8)
    Tx7.sign(private_key1)

    #Negative values
    Tx8 = Tx()
    Tx8.add_input(public_key2, -1)
    Tx8.add_output(public_key1, -1)
    Tx8.sign(private_key2)

    #verify that invalid transactions are caught
    for t in [Tx4, Tx5, Tx6, Tx7, Tx8]:
        i=i+1
        if t.is_valid():
            print("Tx"+str(i)+" ERROR, invalid transaction passed.")
        else:
            print("Tx"+str(i)+" FAILED. Tampering detected.")