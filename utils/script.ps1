# Path to the .bin file containing the shellcode
$shellcodeFilePath = "C:\Users\win10\Desktop\pic_implant\bin\main.bin"

# Read the .bin file as a byte array
$shellcodeBytes = [System.IO.File]::ReadAllBytes($shellcodeFilePath)

# Initialize variables
$output = "db "
$counter = 0

# Loop through the byte array and format it
for ($i = 0; $i -lt $shellcodeBytes.Length; $i++) {
    # Add the byte in hex format
    $output += "0x{0:X2}," -f $shellcodeBytes[$i]

    # Increment the counter
    $counter++

    # Add a newline and "db" every 16 bytes
    if ($counter -eq 16 -and $i -ne $shellcodeBytes.Length - 1) {
        $output += "`n`tdb "
        $counter = 0
    }
}

# Output the formatted shellcode
Write-Host $output