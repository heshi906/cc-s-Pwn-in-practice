import random

# 创建字符列表
char_list = list("abcdefghijklmnopqrstuvwxyz0123456789{}_")

# 随机排序
random.shuffle(char_list)

# 转换成字符串
random_str = "".join(char_list)

print(random_str)
