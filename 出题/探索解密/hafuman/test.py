import heapq

class Node:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other):
        return self.freq < other.freq

def build_huffman_tree(chars, freqs):
    heap = [Node(char, freq) for char, freq in zip(chars, freqs)]
    heapq.heapify(heap)

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)

        merged = Node(None, left.freq + right.freq)
        merged.left = left
        merged.right = right

        heapq.heappush(heap, merged)

    return heap[0]

def huffman_codes(root, code="", mapping=None):
    if mapping is None:
        mapping = {}

    if root is not None:
        if root.char is not None:
            mapping[root.char] = code

        huffman_codes(root.left, code + "0", mapping)
        huffman_codes(root.right, code + "1", mapping)

    return mapping
def encode(string,codes):
    res = ""
    for c in string:
        res += codes[c]
    return res
if __name__ == "__main__":
    chars = 'jkhafum_notv5e!z4{y7wx}01*p)-+g2(#9iq6@&b=dlr^8sc3' 
    freqs = list(range(51, 101))[::-1]  # 生成权重从49到1的列表

    root = build_huffman_tree(chars, freqs)
    codes = huffman_codes(root)

    for char, code in codes.items():
        print(f"字符：{char}, 编码：{code}")
    en=encode('flag{i_like_jk_and_jk_love_me}',codes)
    print(en)
    for i in en:
        char=''
        if i == '1':
            char='j'
        elif i == '0':
            char='k'
        print(char,end='')
