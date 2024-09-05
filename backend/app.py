import subprocess

ArrOutput = []

#NMAP Scanning device function start
def scan_device():
    ip = input("Enter device IP address: ")
    print(f"Scanning device: {ip}")
    result = subprocess.run(["nmap", ip], capture_output=True, text=True)
    print(result.stdout)
# NMAP Scanning device function end

#NMAP Scanning network function start
def scan_network():
    network = input("Enter the network [192.168.1.0/24]: ")
    print(f"Scanning network: {network}")
    try:
        #nmap integration
        result = subprocess.run(["nmap", network], capture_output=True, text=True, timeout=300)  # timeout to prevent hanging
        output = result.stdout
        print(output)
        ArrOutput.append(output) #appends output to a session array

        #Check open ports from output start
        if "open" in output:
            print("Several hosts are detected with open ports.")
            choice = input("Proceed for vulnerability scanning?\n[1] Yes\n[2] Save output to array\n[0] Back to main menu\nEnter choice: ")

            if choice == '1':
                print("Initiating vulnerability scanning...")
            elif choice == '2':
                print("Output saved to array.")
            elif choice == '0':
                print("Returning to main menu.")
            else:
                print("Invalid choice. Returning to main menu.")
        else:
            print("No open ports detected.")
        #Check open ports from output end

    #Try catch error handling
    except subprocess.TimeoutExpired:
        print("The network scan is taking too long and has timed out.")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
# NMAP Scanning network function end

#APPLICATION exit function start
def exit_program():
    print("Exiting the Program.")
    print("Collected Outputs:")
    for idx, output in enumerate(ArrOutput, 1):
        print(f"Output {idx}:")
        print(output)
    return False
#APPLICATION exit function end

#APPLICATION invalid choice handling function start
def invalid_choice():
    print("Invalid choice.")
    return True
#APPLICATION invalid choice handling function end

#NMAP handle scan device function start
def handle_scan_device():
    scan_device()
    return True
#NMAP handle scan device function end

#NMAP handle scan network function start
def handle_scan_network():
    scan_network()
    return True
#NMAP handle scan network function start

#APPLICATION main menu start
def main_menu():
    menu_actions = {
        '1': handle_scan_device,
        '2': handle_scan_network,
        '0': exit_program
    }

    while True:
        print("NMAP Module Menu:")
        print("[1] Scan specific device")
        print("[2] Scan whole network")
        print("[0] Exit")

        choice = input("Enter Choice: ")

        action = menu_actions.get(choice, invalid_choice)
        continue_loop = action()

        if not continue_loop:
            break


if __name__ == "__main__":
    main_menu()
#APPLICATION main menu end