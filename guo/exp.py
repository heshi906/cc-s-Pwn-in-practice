
# 定义一个函数，读取文件的指定页数
def read_file_page(filename, page_number, page_size):
    # 尝试三次，每次增加一页大小的字节数
    for i in range(3):
        for j in range(3):
            size = page_size + j
            # 计算偏移量
            offset = (page_number - 1) * page_size + i
            try:
                # 打开文件，读取指定字节，并返回分行的字符串列表
                with open(filename, 'rb') as file:
                    file.seek(offset)
                    words = file.read(size)
                    return words.decode().split('\n')
            except Exception as e:
                pass
    # 如果三次都失败了，就使用原始的页大小和偏移量
    offset = (page_number - 1) * page_size
    with open(filename, 'rb') as file:
        file.seek(offset)
        words = file.read(page_size)
        return words.split(b'\n')

