#!/bin/bash
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <root_ca_algorithm> <intermediate_ca_algorithm> <ocsp_algorithm> <CN>"
    exit 1
fi


print_frame() {
    local message="$1"
    local border_char="${2:-#}"  # Default border character is '#'
    local border_width=60        # Width of the border
    local padding=2              # Padding lines before and after the message

    # Print the top border
    printf "%${border_width}s\n" | tr " " "$border_char"

    # Add padding before the message
    for ((i = 0; i < padding; i++)); do
        printf "$border_char%$((border_width - 2))s$border_char\n" ""
    done

    # Center the message
    local message_length=${#message}
    local left_padding=$(((border_width - 2 - message_length) / 2))
    printf "$border_char%${left_padding}s%s%$((border_width - 2 - left_padding - message_length))s$border_char\n" "" "$message" ""

    # Add padding after the message
    for ((i = 0; i < padding; i++)); do
        printf "$border_char%$((border_width - 2))s$border_char\n" ""
    done

    # Print the bottom border
    printf "%${border_width}s\n" | tr " " "$border_char"
}


./clean.sh
./gen_root_ca.sh $1
print_frame "ROOT CA GENERATED"
./gen_tls_ca.sh $2
print_frame "TLS CA GENERATED"
./gen_software_ca.sh $2
print_frame "SOFTWARE CA GENERATED"
./setup_ocsp.sh $3
print_frame "OCSP CONFIGURED"
# ./gen_tls_server_cert.sh $4
# print_frame "END ENTITY CERTIFICATE GENERATED (ISSUED BY TLS CA)"