import datetime


def create_file(filename):
    with open("Logs/" + filename, 'w') as f:
        now = datetime.datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f'[{current_time}] Start of the application for ECC file sharing \n')

    f.close()


def log_message(filename, message):
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("Logs/" + filename, 'a') as f:
        f.write(f'[{current_time}] {message} \n')

    f.close()


def log_displayed_text(filename, message, text, file_size):
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("Logs/" + filename, 'a') as f:
        f.write(f'[{current_time}] {message}: {text} | File size: {file_size}B\n')

    f.close()


def log_algorithm(filename, message, algorithm):
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("Logs/" + filename, 'a') as f:
        f.write(f'[{current_time}] {message} | Algorithm used: {algorithm} \n')

    f.close()


def log_file(filename, message, file_size):
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("Logs/" + filename, 'a') as f:
        f.write(f'[{current_time}] {message} | File size: {file_size}B\n')

    f.close()


def log_connection(filename, ip1, ip2, port1, port2):
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("Logs/" + filename, 'a') as f:
        f.write(f'[{current_time}] {ip1} {ip2} {port1} {port2}\n')

    f.close()


def log_all(filename, message, file_size, algorithm):
    now = datetime.datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    with open("Logs/" + filename, 'a') as f:
        f.write(f'[{current_time}] {message} | File size: {file_size}B | Algorithm used: {algorithm}\n')

    f.close()
