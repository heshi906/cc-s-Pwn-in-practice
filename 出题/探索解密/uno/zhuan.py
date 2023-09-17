def replace_bytes_in_file(file_path,file_path2, start, length, replacement):
    with open(file_path, 'rb') as f:
        data = f.read()

    new_data = data[:start] + replacement + data[start+length:]

    with open(file_path2, 'wb') as f:
        f.write(new_data)

# 使用示例
string=b'flag{un0_1s_5o_fun}'[::-1]
replace_bytes_in_file('uno.jpg','question.jpg', 10000, len(string), string)
