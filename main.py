import requests
import hashlib

KNOWN_PASSWORDS = [
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",  # password
    "9D4F9B7BEA7CCCD664D8F1D02EFAF7D5EAA8C71F",  # admin
    "B7F396B54ECBE7E8C26243A1FA0C1ACB3C7DF3A3",  # 12345
    # Добавьте здесь другие известные хеши паролей, если они есть
]

def request_api_data(query_char):
    url = f"https://api.pwnedpasswords.com/range/{query_char}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}, check the API and try again")
    return response

def get_password_leaks_count(hashes, hash_to_check):
    # Хешируем пароль в формате SHA1
    sha1password = hashlib.sha1(hash_to_check.encode('utf-8')).hexdigest().upper()

    # Получаем первые 5 символов хеша
    first5_char, tail = sha1password[:5], sha1password[5:]

    # Проверяем, есть ли известный хеш пароля в списке известных хешей
    if sha1password in KNOWN_PASSWORDS:
        return len(KNOWN_PASSWORDS)

    # Запрашиваем данные по хешу
    response = request_api_data(first5_char)

    # Обрабатываем ответ
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return count
    return 0

def main():
    password = input("Введите пароль: ")
    count = get_password_leaks_count(KNOWN_PASSWORDS, password)
    if count:
        print(f"Пароль '{password}' был найден в {count} утечках. Настоятельно рекомендуется изменить его.")
    else:
        print(f"Пароль '{password}' не был найден в утечках. Продолжайте использовать его безопасно.")

if __name__ == '__main__':
    main()
