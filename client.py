import os
import sys
import time
import argparse
import platform
import socket
import struct
import random
import logging
from ctypes import *

import crypto

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0
ICMP_CHECKSUM = 0
ICMP_ID = 0
DEFAULT_TIMEOUT = 4
DEFAULT_PACKET_SIZE = 1024
MAX_PAYLOAD_SIZE = 1400


class ICMPPacket:
    def __init__(self, packet_type=ICMP_ECHO, code=ICMP_CODE, packet_id=None):
        self.packet_type = packet_type
        self.code = code
        self.checksum = ICMP_CHECKSUM
        self.packet_id = packet_id if packet_id is not None else random.randint(0, 65535)
        self.sequence = 0

    def create_packet(self, data=b''):
        header = struct.pack("!BBHHH", self.packet_type, self.code, 0, self.packet_id, self.sequence)
        
        self.sequence = (self.sequence + 1) % 65536
        
        checksum = self._calculate_checksum(header + data)
        
        header = struct.pack("!BBHHH", self.packet_type, self.code, checksum, self.packet_id, self.sequence - 1)
        
        return header + data

    def _calculate_checksum(self, data):
        checksum = 0
        
        if len(data) % 2:
            data += b'\x00'
        
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        checksum = ~checksum & 0xFFFF
        
        return checksum


def send_file_via_icmp(file_path, server_ip, key, chunk_size=DEFAULT_PACKET_SIZE, timeout=DEFAULT_TIMEOUT):
    if not os.path.exists(file_path):
        logger.error(f"Файл {file_path} не найден")
        return False
    
    file_size = os.path.getsize(file_path)
    logger.info(f"Начинаем передачу файла {file_path} размером {file_size} байт к {server_ip}")
    
    file_name = os.path.basename(file_path)
    
    try:
        if platform.system().lower() == "windows":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        
        sock.settimeout(timeout)
        
        icmp_packet = ICMPPacket()
        
        metadata = f"{file_name}|{file_size}".encode('utf-8')
        encrypted_metadata = crypto.xor_encrypt_decrypt(metadata, key)
        
        packet_data = b'META:' + encrypted_metadata
        
        packet = icmp_packet.create_packet(packet_data)
        sock.sendto(packet, (server_ip, 0))
        logger.info(f"Отправлены метаданные файла: {file_name}, размер: {file_size} байт")
        
        time.sleep(0.5)
        
        encrypted_chunks = crypto.encrypt_file(file_path, key, chunk_size=min(chunk_size, MAX_PAYLOAD_SIZE - 100))
        
        total_chunks = len(encrypted_chunks)
        logger.info(f"Всего блоков для отправки: {total_chunks}")
        
        for i, chunk in enumerate(encrypted_chunks):
            packet_data = struct.pack("!I", i) + chunk
            
            packet = icmp_packet.create_packet(packet_data)
            sock.sendto(packet, (server_ip, 0))
            
            logger.info(f"Отправлен блок {i+1}/{total_chunks}, размер: {len(chunk)} байт")
            
            time.sleep(0.01)
            
        end_marker = b'END:' + crypto.xor_encrypt_decrypt(b'TRANSFER_COMPLETED', key)
        packet = icmp_packet.create_packet(end_marker)
        sock.sendto(packet, (server_ip, 0))
        logger.info("Отправка файла завершена")
        
        return True
        
    except socket.error as e:
        logger.error(f"Ошибка сокета: {e}")
        return False
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
        return False
    finally:
        if 'sock' in locals():
            sock.close()


def main():
    parser = argparse.ArgumentParser(description='Клиент для отправки файлов через ICMP с шифрованием XOR')
    parser.add_argument('file', help='Путь к файлу для отправки')
    parser.add_argument('server_ip', help='IP-адрес сервера')
    parser.add_argument('key', help='Ключ шифрования')
    parser.add_argument('-c', '--chunk-size', type=int, default=DEFAULT_PACKET_SIZE, 
                        help=f'Размер блока для чтения файла (по умолчанию: {DEFAULT_PACKET_SIZE})')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Таймаут ожидания ответа (по умолчанию: {DEFAULT_TIMEOUT})')
    parser.add_argument('-v', '--verbose', action='store_true', help='Детальный вывод')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if platform.system().lower() == "windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            logger.error("Для отправки ICMP пакетов необходимы права администратора")
            print("Для отправки ICMP пакетов необходимо запустить программу с правами администратора")
            return
    
    key_bytes = args.key.encode('utf-8')
    
    success = send_file_via_icmp(args.file, args.server_ip, key_bytes, args.chunk_size, args.timeout)
    
    if success:
        logger.info("Файл успешно отправлен")
    else:
        logger.error("Ошибка при отправке файла")


if __name__ == "__main__":
    main()