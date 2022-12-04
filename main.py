import sys
import threading
import time
from tkinter import *
import socket

global thread_status
keep_alive_flag = True
keep_alive_end = False

switch_roles_flag = False

lock = threading.Lock()
server_loop = True
client_loop = True

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_port = 0;


# ================================================================
#   *** START THE PROGRAM ***
# ================================================================
def dbg(*args, **kwargs):
    msg = ""
    from inspect import currentframe
    frame_obj = sys._getframe(1)  # currentframe()  # get frame of caller function
    line = frame_obj.f_lineno  # source code line number of caller place
    code_obj = frame_obj.f_code  # source code object ( method or function object )
    file_name = code_obj.co_filename  # file name of source code object
    # func     = codeObj.co_name        # method or function name
    # funcLine = codeObj.co_firstlineno # line number where method starts

    msg = "{0}:{1:<4};".format(file_name.rjust(64), line)
    # msg = "{}:{},".format(func, funcLine)
    ct = threading.current_thread()
    msg += "{0:6}; {1};".format(ct.ident, ct.name.ljust(24))

    for a in args:
        msg += "{} ".format(a)
    for k, v in reversed(kwargs.items()):
        msg += "{}={} ".format(k, v)
    with lock:
        print(msg)


def initialize():
    window = Tk()
    window.title("UDP Chat aplication")
    window.geometry("600x580")

    lbl_port = Label(text="PORT:")
    lbl_port.place(x=45, y=50)
    global tb_port
    tb_port = Text(height=1, width=5)
    tb_port.insert(END, "8080")
    tb_port.place(x=85, y=50)

    lbl_ip = Label(text="Ip Address:")
    lbl_ip.place(x=20, y=80)
    global tb_ip
    tb_ip = Text(height=1, width=15)
    tb_ip.insert(END, "127.0.0.1")
    tb_ip.place(x=85, y=80)

    global chb_server, chb_client
    global chb_server_checked
    global chb_client_checked

    chb_server_checked = IntVar()
    chb_client_checked = IntVar()

    chb_server = Checkbutton(text="Server", variable=chb_server_checked, command=on_check_server)
    chb_server.place(x=300, y=50)
    chb_client = Checkbutton(text="Client", variable=chb_client_checked, command=on_check_client)
    chb_client.place(x=300, y=80)
    global btn_start
    btn_start = Button(window, text="Start", command=btn_start_click, width=10)
    btn_start.place(x=490, y=50)
    btn_switch = Button(window, text="Switch", command=btn_switch_click,  width=10)
    btn_switch.place(x=490, y=80)

    global tb_output_text

    chatBox = Scrollbar(window)
    tb_output_text = Text(window, wrap='word', state='disabled', width=60, yscrollcommand=chatBox.set)
    chatBox.configure(command=tb_output_text.yview)
    tb_output_text.place(x=85, y=120)

    lbl_packet_size = Label(text="Packet Size:")
    lbl_packet_size.place(x=20, y=530)
    tb_packet_size = Text(height=1, width=5)
    tb_packet_size.place(x=85, y=530)

    tb_message = Text(height=1, width=40)
    tb_message.place(x=135, y=530)

    btn_message = Button(window, text="Message")
    btn_message.place(x=470, y=530)
    btn_file = Button(window, text="File")
    btn_file.place(x=540, y=530)

    window.mainloop()


# ================================================================
#   Client Handler
# ================================================================

def client_handler(client_socket, server_address):
    dbg("Client")
    global client_loop, switch_roles_flag
    while client_loop:
        if switch_roles_flag:
            switch_roles_flag = False
            client_socket.sendto(str.encode("9"), server_address)
            data, address = client_socket.recvfrom(1500)
            data = data.decode()
            if data == "9":
                tb_output_text.configure(state='normal')
                tb_output_text.insert('end', "Server is going to be a client" + '\n')
                tb_output_text.configure(state='disabled')
                client_loop = False
    dbg("client handler end")


# ================================================================
#   Server Handler
# ================================================================
def server_handler(server_socket, address):
    global server_loop

    while server_loop:

        dbg("waiting recvfrom")
        data = server_socket.recvfrom(1500)  # tu caka, kym nepride message
        info = str(data[0].decode())
        dbg("recvform: ", info, data[1])

        # data = server_socket.recv(1500)
        # info = str(data.decode())

        if info == '4':
            dbg("Keep alive received, Connection is on")
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Keep alive received, Connection is on" + '\n')
            tb_output_text.configure(state='disabled')
            server_socket.sendto(str.encode("4"), address)
            info = ''
        if info == '9':
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "I am going to swich as a Client" + '\n')
            tb_output_text.configure(state='disabled')
            server_socket.sendto(str.encode("9"), address)
            server_loop = False

    dbg("server while end")


# ================================================================
#   Keep Alive
# ================================================================

def keep_alive(client_sock, server_addr, interval):
    global keep_alive_end
    while keep_alive_flag:

        if switch_roles_flag:
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Keep Alive is OFF" + '\n')
            tb_output_text.configure(state='disabled')
            break

        client_sock.sendto(str.encode('4'), server_addr)
        data = client_sock.recv(1500)
        info = str(data.decode())

        if info == '4':
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Connection is working" + '\n')
            tb_output_text.configure(state='disabled')
            print("Connection is working")
        else:
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Connection ended" + '\n')
            tb_output_text.configure(state='disabled')
            print("connection ended")
            break
        time.sleep(interval)
    keep_alive_end = True
    dbg("keep alive end")


# ================================================================
#   Server Login
# ================================================================

def server_login():
    thread = threading.current_thread()
    thread.name = "ServerThread"
    dbg("Server starting...")
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    global server_port, client_loop
    server_port = tb_port.get("1.0", "end-1c")
    server_socket.bind(("0.0.0.0", int(server_port)))  # obsadi si port
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Server is running on port: " + server_port + '\n')
    tb_output_text.configure(state='disabled')
    dbg("waiting recvfrom")
    address = server_socket.recvfrom(1500)
    dbg("recvform:", address[1])
    server_socket.sendto(str.encode("1"), address[1])
    tb_output_text.configure(state='normal')
    tb_output_text.insert('end', "Established connection from address:" + str(address[1]) + '\n')
    tb_output_text.configure(state='disabled')
    dbg("Established connection from address:", address)
    server_handler(server_socket, address[1])

    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()
    time.sleep(1)
    #dbg("thread status", client_thread().is_alive())
    chb_server.deselect()
    chb_client.select()
    on_check_server()
    on_check_client()
    client_loop = True
    client_thread().start()

    dbg("server end")


# ================================================================
#   Client Login
# ================================================================

def client_login():
    thread = threading.current_thread()
    thread.name = "ClientThread"
    dbg("Client starting...")
    flag = 1
    global server_loop
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while flag:
        flag = 0
        try:


            address = tb_ip.get("1.0", "end-1c")
            port = tb_port.get("1.0", "end-1c")
            server_address = (address, int(port))
            client_socket.sendto(str.encode("ahoj"), server_address)

            dbg("server_address: ", server_address)
            client_socket.settimeout(60)
            data, address = client_socket.recvfrom(1500)
            data = data.decode()
            if data == "1":
                tb_output_text.configure(state='normal')
                tb_output_text.insert('end', "Connected to address:" + str(server_address) + '\n')
                tb_output_text.configure(state='disabled')
                keep_alive_thread(client_socket, server_address, 5).start()
                client_handler(client_socket, server_address)

                dbg("Connected to address:", server_address)

        except (socket.timeout, socket.gaierror) as e:
            print(e)
            tb_output_text.configure(state='normal')
            tb_output_text.insert('end', "Connection not working try again", '\n')
            tb_output_text.configure(state='disabled')
            print("Connection not working try again")
            continue
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()
    # while True:
    #     tb_output_text.configure(state='normal')
    #     tb_output_text.insert('end', "Shutting down keep alive" + '\n')
    #     tb_output_text.configure(state='disabled')
    #     if keep_alive_end:
    #         break
    server_loop = True
    chb_server.select()
    chb_client.deselect()
    on_check_server()
    on_check_client()
    server_thread().start()
    dbg("client end")


# ================================================================
#  Start
# ================================================================
def client_thread():
    return threading.Thread(target=client_login)

def server_thread():
    return threading.Thread(target=server_login)

def keep_alive_thread(client_socket, server_address, interval):
    return threading.Thread(target=keep_alive, args=(client_socket, server_address, interval))


def start():
    if chb_client_checked.get():
        client_thread().start()
    elif chb_server_checked.get():
        server_thread().start()


# ================================================================
#  Button Start Click
# ================================================================

def on_check_client():
    if chb_client_checked.get() == 1:
        chb_client["fg"] = "green"
    else:
        chb_client["fg"] = "red"

def on_check_server():
    if chb_server_checked.get() == 1:
        chb_server["fg"] = "green"
    else:
        chb_server["fg"] = "red"


def btn_start_click():
    dbg("btn_start_click")
    btn_start["text"] = "Running"
    btn_start["bg"] = "green"
    btn_start["disabledforeground"] = "red"
    btn_start["state"] = DISABLED
    start()

def btn_switch_click():

    dbg("btn_switch_click")
    global switch_roles_flag, server_loop
    switch_roles_flag = True
    keep_alive_flag = False
    server_loop = False
    # global server_port
    # server_address = ("127.0.0.1", int(server_port))
    # client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # client_socket.sendto(str.encode("11"), server_address)
    # client_socket.shutdown(socket.SHUT_RDWR)
    # client_socket.close()

initialize()

# def Client_handler():

# def Send_to_server():

# def Recieve_from_server():

# ================================================================
#   *** SERVER ***
# ================================================================

# def Server():


# def Send_to_client():

# def Recieve_from_client():

# ================================================================
#   *** GENERAL FUNCTIONS ***
# ================================================================

# def Keep_alive_send():

# def Keep_alive_recieve():

# def Switch_roles():
