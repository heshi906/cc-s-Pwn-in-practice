import os

input_str = input()
with open("input.js", "w") as f:
    while input_str:
        f.write(input_str+'\n')
        input_str = input()

os.system("./d8 input.js")


exit(0)
