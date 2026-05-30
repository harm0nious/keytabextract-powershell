function Display-Help {
    Write-Host "KeyTabExtract. Extract NTLM Hashes from KeyTab files where RC4-HMAC encryption has been used."
    Write-Host "Usage : .\keytabextract.ps1 [keytabfile]"
    Write-Host "Example : .\keytabextract.ps1 service.keytab"
}

function Safe-Substring ($str, $start, $length) {
    if ($start -ge $str.Length) { return "" }
    if (($start + $length) -gt $str.Length) {
        return $str.Substring($start)
    }
    return $str.Substring($start, $length)
}

function Convert-HexToString ($hexString) {
    if ([string]::IsNullOrEmpty($hexString)) { return "" }
    try {
        $bytes = New-Object Byte[] ($hexString.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($hexString.Substring(($i * 2), 2), 16)
        }
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        return ""
    }
}

function Invoke-KTExtract ($hexEncoded) {
    $rc4hmac = $false
    $aes128 = $false
    $aes256 = $false 
    
    if ($hexEncoded -like "*00170010*") {
        Write-Host "[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash."
        $rc4hmac = $true
    } else {
        Write-Host "[!] No RC4-HMAC located. Unable to extract NTLM hashes."
    }
        
    if ($hexEncoded -like "*00120020*") {
        Write-Host "[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction."
        $aes256 = $true
    } else {
        Write-Host "[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes."
    }

    if ($hexEncoded -like "*00110010*") {
        Write-Host "[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction."
        $aes128 = $true
    } else {
        Write-Host "[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes."
    }

    if (-not $rc4hmac -and -not $aes256 -and -not $aes128) {
        Write-Host "Unable to find any useful hashes.`nExiting..."
        return
    }

    $ktversion = Safe-Substring $hexEncoded 0 4
    if ($ktversion -eq '0502') {
        Write-Host "[+] Keytab File successfully imported."
    } else {
        Write-Host "[!] Only Keytab versions 0502 are supported.`nExiting..."
        return
    }

    $arrLen = [Convert]::ToInt32((Safe-Substring $hexEncoded 4 8), 16)

    $num_components = Safe-Substring $hexEncoded 12 4

    $num_realm = [Convert]::ToInt32((Safe-Substring $hexEncoded 16 4), 16)

    $realm_jump = 20 + ($num_realm * 2)

    $realmHex = Safe-Substring $hexEncoded 20 ($realm_jump - 20)
    $realmStr = Convert-HexToString $realmHex
    Write-Host "`tREALM : $realmStr"

    $comp_array_calc = $realm_jump + 4
    $comp_array = [Convert]::ToInt32((Safe-Substring $hexEncoded $realm_jump 4), 16)

    $comp_array_offset = $comp_array_calc + ($comp_array * 2)
    $comp_array2Hex = Safe-Substring $hexEncoded $comp_array_calc ($comp_array_offset - $comp_array_calc)

    $principal_array_offset = $comp_array_offset + 4

    $principal_array = Safe-Substring $hexEncoded $comp_array_offset 4
    $principal_array_int = ([Convert]::ToInt32($principal_array, 16) * 2)
    $prin_array_start = $principal_array_offset
    $prin_array_finish = $prin_array_start + $principal_array_int
    $principal_array_valueHex = Safe-Substring $hexEncoded $prin_array_start ($prin_array_finish - $prin_array_start)
    
    $compStr = Convert-HexToString $comp_array2Hex
    $prinStr = Convert-HexToString $principal_array_valueHex
    Write-Host "`tSERVICE PRINCIPAL : $compStr/$prinStr"

    $typename_offset = $prin_array_finish + 8
    $typename = Safe-Substring $hexEncoded $prin_array_finish 8

    $timestamp_offset = $typename_offset + 8
    $timestamp = Safe-Substring $hexEncoded $typename_offset 8

    $vno_offset = $timestamp_offset + 2
    $vno = Safe-Substring $hexEncoded $timestamp_offset 2

    $keytype_offset = $vno_offset + 4
    $keytype_hex = Safe-Substring $hexEncoded $vno_offset 4
    if ($keytype_hex) { $keytype_dec = [Convert]::ToInt32($keytype_hex, 16) }

    $key_val_offset = $keytype_offset + 4
    $key_val_hex = Safe-Substring $hexEncoded $keytype_offset 4
    if ($key_val_hex) { $key_val_len = [Convert]::ToInt32($key_val_hex, 16) }

    if ($key_val_len) {
        $key_val_start = $key_val_offset
        $key_val_finish = $key_val_start + ($key_val_len * 2)
        $key_val = Safe-Substring $hexEncoded $key_val_start ($key_val_finish - $key_val_start)
    }

    if ($rc4hmac -eq $true) {
        $split = $hexEncoded -split "00170010"
        if ($split.Count -gt 1) {
            $NTLMHash = $split[1]
            $len = [Math]::Min(32, $NTLMHash.Length)
            Write-Host "`tNTLM HASH : $($NTLMHash.Substring(0, $len))"
        }
    }

    if ($aes256 -eq $true) {
        $split = $hexEncoded -split "00120020"
        if ($split.Count -gt 1) {
            $aes256hash = $split[1]
            $len = [Math]::Min(64, $aes256hash.Length)
            Write-Host "`tAES-256 HASH : $($aes256hash.Substring(0, $len))"
        }
    }

    if ($aes128 -eq $true) {
        $split = $hexEncoded -split "00110010"
        if ($split.Count -gt 1) {
            $aes128hash = $split[1]
            $len = [Math]::Min(32, $aes128hash.Length)
            Write-Host "`tAES-128 HASH : $($aes128hash.Substring(0, $len))"
        }
    }
}

if ($args.Count -eq 0) {
    Display-Help
    Exit
}

$ktfile = $args[0]

if (-not (Test-Path $ktfile)) {
    Write-Host "[!] File not found: $ktfile"
    Exit
}

try {
    $fileBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $ktfile))
    $hex_encoded = [System.BitConverter]::ToString($fileBytes).Replace("-", "").ToLower()
    Invoke-KTExtract $hex_encoded
} catch {
    Write-Host "[!] Error reading or parsing file: $_"
}
