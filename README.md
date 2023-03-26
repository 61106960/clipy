# clipy

![](https://github.com/61106960/clipy/raw/main/images/clipy.jpg)

clipy is a Powershell tool to help you copy/paste files via RDP/ICA.

As said, clipy can help you copy/paste files into restricted remote desktop environments, e.g. via RDP/ICA, where it is not possible to copy files directly to it and copy/paste of ASCII via the clipboard is the only way.

# How It Works

clipy can be run simply by starting the Powershell script via _invoke-clipy_ with some additional parameters. As it consists of a sender and a receiver, you have to start it twice, on your own source machine where your source files are stored and on the target machine where you want to copy the files to.  

clipy takes your input file at the source machine, do some gzip compression, AES encryption, Base64 encoding and splits it in chunks with 2MB by default.  
On the target receiver side, it takes the single chunks until it have received everything, puts all together, AES decrypts and gzip decompress the data. The received data will either be stored on the filesystem of the target system or, if your source file is a Powershell script, can directly be executed in the Powershell process if you like.

As nice add-on, you can use clipy to build AES encrypted output files of source Powershell files and later on, read this encrypted files in the targets Powershell process, decrypt and executes it. If needed, you can execute an AMSI bypass to, to get your own Powershell script started. 

## Step by Step
Let's jump to the details. After you have imported clipy to Powershell on both machines you starting it first on your source machine and point to the source file you want to copy to the target machine. clipy will do its tasks and provide you with some infos of the file and the current chunk will be copied to the clipboard directly.  
Now it is time to start clipy on your target computer. clipy will read the clipboard directly and try to detect if the clipboard content is a valid clipy chunk. If yes, it will show you the chunk number it has received and for convenience purpose a SHA1 hash of the chunk, which you can check with the one from the source clipy instance. As mentioned, it is just for convenience as clipy will check if the received chunk is valid and not damaged.  
If your source file was a small one or you adjusted the max chunk size you may be lucky and you have finished already. Likely your input file was much larger or the size of possible clipboard data is limited, then you have to jump back to your source clipy instance, hit _ENTER_, to get the next chunk to your clipboard, jump to the target and hit _ENTER_ again, to let clipy read the content from the clipboard.

You will have to do this tasks again and again until all the chunks are on the target side. Some important note should be mentioned. Your chunks have to be in the right order. Although clipy does neither import damaged chunks nor non-clipy data, you must provide the chunks in the right order. e.g. 1,2,3,4....

## clipy Functions

clipy consists of the following functions:
* Action - Select if clipy is in _Sender_ or _Receiver_ mode or use _CryptFileWrite_ and _CryptFileRead_ to build an AES encrypted output file or read it back in again.
* PSH - If the source file is a Powershell file, you can import its modules directly in the target Powershell process with _Import_ or just execute the Powershell code with _Excute_, both variants execute your Powershell code without storing the file to disk.
* AMSI - Executes an AMSI bypass in the target Powershell process before you import modules or execute code.


# Some How To Use Examples
### First you have to load clipy in Powershell...
```
Import-Module .\clipy.ps1
```
or
```
. .\clipy.ps1
```
or
```
gc -raw .\clipy.ps1 | iex
```
or
```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/61106960/clipy/main/clipy.ps1')
```

## Usage in sender mode
### Read the source file from the source computer

clipy reads the source file "source-file.exe" and splits it in 2MB chunks.
```
Invoke-Clipy -Action Send -InputFile "source-file.exe"
```

clipy reads the source file "source-file.exe" and splits it in 1.4MB chunks.
```
Invoke-Clipy -Action Send -InputFile "source-file.exe" -maxSize 1.4MB
```

clipy reads the source file "source-file.exe", use a specific AES encryption key instead of the default one and splits it in 4MB chunks.
```
Invoke-Clipy -Action Send -InputFile "source-file.exe" -AESKey "Secr3tP8ssw0rd!" -maxSize 4MB
```

clipy reads the source file "source-file.ps1" and stores it as AES encrypted output file.
```
Invoke-Clipy -Action CryptFileWrite -InputFile "source-file.ps1" -OutputFile "crypted-ps1.txt"
```

### How it looks like in action
![](https://github.com/61106960/clipy/raw/main/images/clipy-sender.png)


## Usage in receiver mode
### Write the target file on the target computer

clipy writes the received file as "target-file.exe".
```
Invoke-Clipy -Action Receive -OutputFile "target-file.exe"
```

clipy writes the received file as "target-file.exe", use a specific AES decryption key instead of the default one and force overwriting the target file if it is existing already.
```
Invoke-Clipy -Action Receive -OutputFile "target-file.exe" -AESKey "Secr3tP8ssw0rd!" -Force
```

### How it looks like in action
![](https://github.com/61106960/clipy/raw/main/images/clipy-receiver-file.png)


### Executes the Powershell source file on the target computer

Clipy imports the Powershell modules of the received Powershell file.
```
Invoke-Clipy -Action Receive -PSH Import
```

Clipy executes an AMSI bypass before it imports the modules of the received Powershell file and uses a specific AES decryption key instead of the default one.
```
Invoke-Clipy -Action Receive -PSH Import -AMSI -AESKey "Secr3tP8ssw0rd!"
```

Clipy executes an AMSI bypass before it executes the received Powershell file.
```
Invoke-Clipy -Action Receive -PSH Execute -AMSI
```

### How it looks like in action
Sender  
![](https://github.com/61106960/clipy/raw/main/images/clipy-receiver-ps1.png)

Receiver  
![](https://github.com/61106960/clipy/raw/main/images/clipy-receiver-ps1.png)

### Read the encrypted Powershell source file on the target computer and execute it

Clipy executes an AMSI bypass before it imports the modules of the AES encrypted Powershell input file.
```
Invoke-Clipy -Action CryptFileRead - InputFile "crypted-ps1.txt" -PSH Import -AMSI
```

Clipy executes an AMSI bypass before it executes the AES encrypted Powershell input file.
```
Invoke-Clipy -Action CryptFileRead -InputFile "crypted-ps1.txt" -PSH Execute -AMSI
```

### How it looks like in action
Sender  
![](https://github.com/61106960/clipy/raw/main/images/clipy-receiver-crypt1.png)

Receiver  
![](https://github.com/61106960/clipy/raw/main/images/clipy-receiver-crypt2.png)