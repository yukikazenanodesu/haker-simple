# -*- coding: utf-8 -*-
import time
from platform import system
from psutil import net_if_addrs, net_io_counters

def wdawd(info):
    recv_bytes = wdawdawhv(info[0])
    sent_bytes = wdawdawhv(info[1])
    recv_pak = str(info[2]) + " pak/s"
    sent_pak = str(info[3]) + " pak/s"
    return recv_bytes, sent_bytes, recv_pak, sent_pak
def wibjx():
    system_name = system()
    netcard_name = wdaw()
    if system_name == "Windows":
        import wmi
        wmi_obj = wmi.WMI()
        data = {}
        for nic in wmi_obj.Win32_NetworkAdapterConfiguration():
            if nic.MACAddress is not None:
                mac_address = str(nic.MACAddress).replace(':', '-')
                if mac_address in netcard_name.keys():
                    net_card_name = netcard_name.get(mac_address)
                    nic_name = str(nic.Caption)[11:]
                    data.update({net_card_name: nic_name})
        return (system_name, data)
    elif system_name == "Linux":
        List = list(netcard_name.values())
        return (system_name, List)
    else:
        return None
def wdajvjb(net_card):
    net_info = net_io_counters(pernic=True).get(net_card)  #获取流量统计信息
    recv_bytes = net_info.bytes_recv
    sent_bytes = net_info.bytes_sent
    recv_pak = net_info.packets_recv
    sent_pak = net_info.packets_sent
    return recv_bytes, sent_bytes, recv_pak, sent_pak
def sviawwq(time_stamp):
    delta_ms = str(time_stamp - int(time_stamp))
    time_temp = time.localtime(time_stamp)
    my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)
    my_time += delta_ms[1:8]
    return my_time
def wdaw():
    netcard_info = {}
    info = net_if_addrs()
    for k, v in info.items():
        for item in v:
            if item[0] == 2 and item[1] == '127.0.0.1':
                break
            elif item[0] == -1 or item[0] == 17:
                netcard_info.update({item[1]: k})
    return netcard_info
def wdawdawhv(count):
    if count < 1024:
        return "%.2f B/s" % count
    if count < 1048576:
        return "%.2f KB/s" % (count / 1024)
    count >>= 10
    if count < 1048576:
        return "%.2f MB/s" % (count / 1024)
    count >>= 10
    return "%.2f GB/s" % (count / 1024)
def wvisv(net_card):
    net_cards = []
    old = [0, 0, 0, 0]
    new = [0, 0, 0, 0]
    if net_card is None:
        net_cards = net_io_counters(pernic=True).keys()
    else:
        net_cards.append(net_card)
    for card in net_cards:
        info = wdajvjb(card)
        for i in range(4):
            old[i] += info[i]
    time.sleep(1)
    for card in net_cards:
        info = wdajvjb(card)
        for i in range(4):
            new[i] += info[i]
    info = []
    for i in range(4):
        info.append(new[i] - old[i])
    return info