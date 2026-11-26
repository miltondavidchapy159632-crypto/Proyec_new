$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('192.168.56.102'), 8080)
$listener.Start()
Write-Output 'Servicio de laboratorio escuchando en 192.168.56.102:8080'
while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $reader = [System.IO.StreamReader]::new($stream)
    $null = $reader.ReadLine()
    $body = "Laboratorio IDS activo`n"
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $headers = "HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
    $response = [System.Text.Encoding]::UTF8.GetBytes($headers + $body)
    $stream.Write($response, 0, $response.Length)
    $stream.Flush()
    $client.Close()
}
