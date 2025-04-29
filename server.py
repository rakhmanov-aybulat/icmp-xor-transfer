import os
import sys
import time
import argparse
import socket
import struct
import logging
import binascii
from collections import defaultdict

import crypto

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_HEADER_SIZE = 8
IP_HEADER_SIZE = 20

DEFAULT_OUTPUT_DIR = './received_files'
DEFAULT_TIMEOUT = 60 * 5 


class ICMPPacketParser:
    @staticmethod
    def extract_icmp_data(packet):
        icmp_header = packet[IP_HEADER_SIZE:IP_HEADER_SIZE + ICMP_HEADER_SIZE]
        
        icmp_type, icmp_code, _, packet_id, sequence = struct.unpack("!BBHHH", icmp_header)
        
        data = packet[IP_HEADER_SIZE + ICMP_HEADER_SIZE:]
        
        return icmp_type, icmp_code, packet_id, sequence, data


class FileReceiver:
    def __init__(self, key, output_dir=DEFAULT_OUTPUT_DIR, timeout=DEFAULT_TIMEOUT):
        self.key = key
        self.output_dir = output_dir
        self.timeout = timeout
        self.parser = ICMPPacketParser()
        self.file_chunks = defaultdict(dict)
        self.file_metadata = {}
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
    
    def start_receiver(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            logger.info(f"Сервер запущен. Ожидание входящих ICMP-пакетов...")
            logger.info(f"Файлы будут сохранены в директорию: {self.output_dir}")
            logger.info(f"Таймаут ожидания: {self.timeout} секунд")
            
            last_packet_time = time.time()
            
            current_sender = None
            file_complete = False
            
            while time.time() - last_packet_time < self.timeout:
                packet, addr = sock.recvfrom(65565)
                sender_ip = addr[0]
                
                if current_sender is None:
                    current_sender = sender_ip
                    logger.info(f"Получение пакетов от {current_sender}")
                
                if sender_ip == current_sender:
                    last_packet_time = time.time()
                    
                    _, _, packet_id, sequence, data = self.parser.extract_icmp_data(packet)
                    
                    file_complete = self._process_packet_data(sender_ip, packet_id, sequence, data)
                    
                    if file_complete:
                        current_sender = None
                        file_complete = False
                
                if file_complete or (time.time() - last_packet_time >= self.timeout):
                    if current_sender:
                        self._try_assemble_file(current_sender)
                    
                    current_sender = None
                    last_packet_time = time.time()
            
            logger.info("Таймаут ожидания пакетов. Выход из программы.")
            
        except KeyboardInterrupt:
            logger.info("Прерывание пользователем. Выход из программы.")
        except socket.error as e:
            logger.error(f"Ошибка сокета: {e}")
        finally:
            if 'sock' in locals():
                sock.close()
    
    def _process_packet_data(self, sender_ip, packet_id, sequence, data):
        if data.startswith(b'META:'):
            meta_data = data[5:]
            decrypted_meta = crypto.xor_encrypt_decrypt(meta_data, self.key)
            
            try:
                meta_str = decrypted_meta.decode('utf-8')
                file_name, file_size = meta_str.split('|')
                file_size = int(file_size)
                
                self.file_metadata[sender_ip] = {
                    'file_name': file_name,
                    'file_size': file_size,
                    'total_chunks': 0,
                    'start_time': time.time()
                }
                
                logger.info(f"Получены метаданные файла от {sender_ip}: {file_name}, размер: {file_size} байт")
                
            except (UnicodeDecodeError, ValueError) as e:
                logger.error(f"Ошибка при обработке метаданных: {e}")
            
            return False
        
        elif data.startswith(b'END:'):
            if sender_ip in self.file_metadata:
                logger.info(f"Получен маркер завершения передачи файла от {sender_ip}")
                return self._try_assemble_file(sender_ip)
            return False
        
        else:
            try:
                chunk_index = struct.unpack("!I", data[:4])[0]
                chunk_data = data[4:]
                
                if sender_ip in self.file_metadata:
                    self.file_chunks[sender_ip][chunk_index] = chunk_data
                    
                    if len(self.file_chunks[sender_ip]) % 100 == 0:
                        logger.info(f"Получено {len(self.file_chunks[sender_ip])} блоков данных от {sender_ip}")
                
                return False
                
            except struct.error:
                logger.error(f"Ошибка при извлечении номера блока из пакета")
                return False
    
    def _try_assemble_file(self, sender_ip):
        if sender_ip not in self.file_metadata or sender_ip not in self.file_chunks:
            logger.error(f"Нет метаданных или блоков для {sender_ip}")
            return False
        
        metadata = self.file_metadata[sender_ip]
        chunks = self.file_chunks[sender_ip]
        
        logger.info(f"Получено {len(chunks)} блоков данных от {sender_ip}")
        
        sorted_chunks = [chunks[i] for i in sorted(chunks.keys())]
        
        decrypted_data = crypto.decrypt_chunks(sorted_chunks, self.key)
        
        output_path = os.path.join(self.output_dir, metadata['file_name'])
        
        if os.path.exists(output_path):
            timestamp = int(time.time())
            filename, extension = os.path.splitext(metadata['file_name'])
            output_path = os.path.join(self.output_dir, f"{filename}_{timestamp}{extension}")
        
        try:
            crypto.save_to_file(decrypted_data, output_path)
            
            received_size = os.path.getsize(output_path)
            expected_size = metadata['file_size']
            
            if received_size == expected_size:
                logger.info(f"Файл {output_path} успешно получен и сохранен")
                logger.info(f"Размер: {received_size} байт, совпадает с ожидаемым")
            else:
                logger.warning(f"Файл {output_path} сохранен, но размер не совпадает")
                logger.warning(f"Получено: {received_size} байт, ожидалось: {expected_size} байт")
            
            del self.file_chunks[sender_ip]
            del self.file_metadata[sender_ip]
            
            return True
            
        except IOError as e:
            logger.error(f"Ошибка при сохранении файла {output_path}: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Сервер для приема файлов через ICMP с дешифрованием XOR')
    parser.add_argument('key', help='Ключ дешифрования')
    parser.add_argument('-o', '--output-dir', default=DEFAULT_OUTPUT_DIR,
                        help=f'Директория для сохранения полученных файлов (по умолчанию: {DEFAULT_OUTPUT_DIR})')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Таймаут ожидания пакетов в секундах (по умолчанию: {DEFAULT_TIMEOUT})')
    parser.add_argument('-v', '--verbose', action='store_true', help='Детальный вывод')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if os.geteuid() != 0:
        logger.error("Для приема ICMP пакетов необходимы права root")
        print("Для приема ICMP пакетов необходимо запустить программу с правами root (sudo)")
        return
    
    key_bytes = args.key.encode('utf-8')
    
    receiver = FileReceiver(key_bytes, args.output_dir, args.timeout)
    receiver.start_receiver()


if __name__ == "__main__":
    main()